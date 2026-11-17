use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tower_http::services::ServeDir;

// ---------------------------------------------------------------------------
// 可验证抽签协议(与前端 static/app.js 中的实现必须保持逐字节一致)
//
// 1. 名单规范化: 每行 "id:name",按提交顺序用 "\n" 连接(无尾部换行),UTF-8。
// 2. list_hash  = SHA-256(规范化名单)
// 3. 服务器秘密 server_seed = 32 字节随机数,创建时生成,开奖后才公开。
//    commitment = SHA-256(server_seed)              —— 开奖前公布
// 4. 公开随机源(本地模拟): 按 60 秒一轮,每轮的值在该轮开始后才生成并公布,
//    模拟"事后才确定"的外部随机源(生产环境应换成 drand / NIST Beacon /
//    未来比特币区块哈希等)。
// 5. seed = SHA-256("lottery-v1" || server_seed || public_random || list_hash)
//    (三个字段均为原始字节,不是 hex 字符串)
// 6. 确定性随机数: rand_u64(i) = SHA-256(seed || i_be_bytes_8) 的前 8 字节(大端)
// 7. 抽奖: 奖池初始为名单顺序;按奖项顺序逐个抽取:
//    j = rand_u64(counter) % 剩余人数; 取出 pool[j]; counter 递增。
// ---------------------------------------------------------------------------

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

fn canonical_list(participants: &[Participant]) -> String {
    participants
        .iter()
        .map(|p| format!("{}:{}", p.id, p.name))
        .collect::<Vec<_>>()
        .join("\n")
}

fn list_hash(participants: &[Participant]) -> [u8; 32] {
    sha256(canonical_list(participants).as_bytes())
}

fn final_seed(server_seed: &[u8; 32], public_random: &[u8; 32], list_hash: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(10 + 96);
    buf.extend_from_slice(b"lottery-v1");
    buf.extend_from_slice(server_seed);
    buf.extend_from_slice(public_random);
    buf.extend_from_slice(list_hash);
    sha256(&buf)
}

fn rand_u64(seed: &[u8; 32], counter: u64) -> u64 {
    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(seed);
    buf.extend_from_slice(&counter.to_be_bytes());
    let h = sha256(&buf);
    u64::from_be_bytes(h[..8].try_into().unwrap())
}

fn run_draw(participants: &[Participant], prizes: &[Prize], seed: &[u8; 32]) -> Vec<Winner> {
    let mut pool: Vec<Participant> = participants.to_vec();
    let mut counter: u64 = 0;
    let mut winners = Vec::new();
    for prize in prizes {
        for _ in 0..prize.count {
            if pool.is_empty() {
                return winners;
            }
            let j = (rand_u64(seed, counter) % pool.len() as u64) as usize;
            counter += 1;
            let w = pool.remove(j);
            winners.push(Winner {
                prize: prize.name.clone(),
                id: w.id,
                name: w.name,
            });
        }
    }
    winners
}

// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct Participant {
    id: String,
    name: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Prize {
    name: String,
    count: usize,
}

#[derive(Clone, Serialize)]
struct Winner {
    prize: String,
    id: String,
    name: String,
}

#[derive(Clone, Serialize)]
struct BeaconValue {
    round: u64,
    value: String,      // hex, 32 字节
    generated_at: u64,  // unix 秒
}

#[derive(Clone, Serialize)]
struct Session {
    id: String,
    name: String,
    participants: Vec<Participant>,
    prizes: Vec<Prize>,
    list_hash: String,
    commitment: String,
    committed_at: u64,
    status: String, // "committed" | "drawn"
    // 以下字段开奖后才公开
    server_seed: Option<String>,
    public_random: Option<BeaconValue>,
    winners: Option<Vec<Winner>>,
}

#[derive(Default)]
struct AppState {
    sessions: HashMap<String, SessionInner>,
    beacons: HashMap<u64, BeaconValue>,
}

struct SessionInner {
    public: Session,
    secret_seed: [u8; 32], // 开奖前绝不离开服务器
}

#[derive(Deserialize)]
struct CreateSession {
    name: String,
    participants: Vec<Participant>,
    prizes: Vec<Prize>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// 模拟公开随机源:每 60 秒一轮,轮次开始后才生成该轮的值。
fn beacon_for_round(state: &mut AppState, round: u64) -> BeaconValue {
    if let Some(b) = state.beacons.get(&round) {
        return b.clone();
    }
    let mut v = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut v);
    let b = BeaconValue {
        round,
        value: to_hex(&v),
        generated_at: now_secs(),
    };
    state.beacons.insert(round, b.clone());
    b
}

async fn create_session(
    State(state): State<Arc<Mutex<AppState>>>,
    Json(req): Json<CreateSession>,
) -> impl IntoResponse {
    if req.participants.is_empty() || req.prizes.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "participants and prizes must be non-empty",
        )
            .into_response();
    }
    let mut ids = std::collections::HashSet::new();
    for p in &req.participants {
        if p.id.contains(':') || p.name.contains(':') || p.id.contains('\n') || p.name.contains('\n') {
            return (StatusCode::BAD_REQUEST, "id/name must not contain ':' or newline").into_response();
        }
        if !ids.insert(p.id.clone()) {
            return (StatusCode::BAD_REQUEST, "duplicate participant id").into_response();
        }
    }

    let lh = list_hash(&req.participants);
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    let commitment = sha256(&secret);

    let mut id_bytes = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut id_bytes);
    let id = to_hex(&id_bytes);

    let session = Session {
        id: id.clone(),
        name: req.name,
        participants: req.participants,
        prizes: req.prizes,
        list_hash: to_hex(&lh),
        commitment: to_hex(&commitment),
        committed_at: now_secs(),
        status: "committed".into(),
        server_seed: None,
        public_random: None,
        winners: None,
    };
    state
        .lock()
        .unwrap()
        .sessions
        .insert(id, SessionInner { public: session.clone(), secret_seed: secret });
    Json(session).into_response()
}

async fn list_sessions(State(state): State<Arc<Mutex<AppState>>>) -> impl IntoResponse {
    let state = state.lock().unwrap();
    let mut v: Vec<&Session> = state.sessions.values().map(|s| &s.public).collect();
    v.sort_by_key(|s| s.committed_at);
    Json(v).into_response()
}

async fn get_session(
    State(state): State<Arc<Mutex<AppState>>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let state = state.lock().unwrap();
    match state.sessions.get(&id) {
        Some(s) => Json(s.public.clone()).into_response(),
        None => (StatusCode::NOT_FOUND, "session not found").into_response(),
    }
}

async fn draw(
    State(state): State<Arc<Mutex<AppState>>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut state = state.lock().unwrap();
    // 取当前轮次的公开随机值(该值在本轮开始前不存在)
    let round = now_secs() / 60;
    let beacon = beacon_for_round(&mut state, round);

    let Some(inner) = state.sessions.get_mut(&id) else {
        return (StatusCode::NOT_FOUND, "session not found").into_response();
    };
    if inner.public.status == "drawn" {
        return (StatusCode::CONFLICT, "already drawn").into_response();
    }
    let Some(public_bytes) = from_hex(&beacon.value).and_then(|v| <[u8; 32]>::try_from(v).ok()) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "bad beacon value").into_response();
    };
    let lh = list_hash(&inner.public.participants);
    let seed = final_seed(&inner.secret_seed, &public_bytes, &lh);
    let winners = run_draw(&inner.public.participants, &inner.public.prizes, &seed);

    // 开奖:公开 server_seed 与公开随机源,任何人可复算
    inner.public.server_seed = Some(to_hex(&inner.secret_seed));
    inner.public.public_random = Some(beacon);
    inner.public.winners = Some(winners);
    inner.public.status = "drawn".into();
    Json(inner.public.clone()).into_response()
}

#[tokio::main]
async fn main() {
    let state = Arc::new(Mutex::new(AppState::default()));
    let app = Router::new()
        .route("/api/sessions", post(create_session).get(list_sessions))
        .route("/api/sessions/:id", get(get_session))
        .route("/api/sessions/:id/draw", post(draw))
        .fallback_service(ServeDir::new("static"))
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "9317".into());
    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("listening on http://127.0.0.1:{port}");
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ps(names: &[&str]) -> Vec<Participant> {
        names
            .iter()
            .enumerate()
            .map(|(i, n)| Participant { id: format!("{:03}", i + 1), name: n.to_string() })
            .collect()
    }

    #[test]
    fn draw_is_deterministic_and_no_duplicates() {
        let participants = ps(&["甲", "乙", "丙", "丁", "戊", "己", "庚"]);
        let prizes = vec![
            Prize { name: "一等奖".into(), count: 1 },
            Prize { name: "二等奖".into(), count: 2 },
        ];
        let seed = sha256(b"test-seed");
        let w1 = run_draw(&participants, &prizes, &seed);
        let w2 = run_draw(&participants, &prizes, &seed);
        assert_eq!(w1.len(), 3);
        assert_eq!(w1[0].prize, "一等奖");
        let ids: std::collections::HashSet<_> = w1.iter().map(|w| &w.id).collect();
        assert_eq!(ids.len(), 3, "winners must be distinct");
        assert!(w1.iter().zip(w2.iter()).all(|(a, b)| a.id == b.id), "deterministic");
    }

    #[test]
    fn commitment_binds_seed() {
        let secret = sha256(b"some secret");
        assert_eq!(to_hex(&sha256(&secret)), to_hex(&sha256(&secret)));
        let other = sha256(b"other");
        assert_ne!(sha256(&secret), sha256(&other));
    }

    #[test]
    fn list_hash_detects_tampering() {
        let a = ps(&["张三", "李四"]);
        let mut b = a.clone();
        b[0].name = "张四".into();
        assert_ne!(list_hash(&a), list_hash(&b));
        // 顺序也参与承诺
        let mut c = a.clone();
        c.swap(0, 1);
        assert_ne!(list_hash(&a), list_hash(&c));
    }
}
