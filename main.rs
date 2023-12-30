use std::io::{self, Write};
use futures::SinkExt;
use serde_json::json;
use tokio_tungstenite::connect_async;
use tungstenite::protocol::Message;


struct Constr {
    url: String,
    port: String,
}

impl Constr {
    fn set(url: &str, port: &str) -> Constr {
        Constr {
            url: url.to_string(),
            port: port.to_string(),
        }
    }
}

#[tokio::main]
async fn main() {
    let seturl: Constr = Constr::set("ws://localhost", "3000");

    let url = format!("{}:{}", seturl.url, seturl.port);

    println!("{}", "Connecting to chat server...");
    let (mut ws, _) = connect_async(&url).await.expect("Connection Error");
    println!("{}", "Connected Successfully!");

    tokio::spawn(msg_handle(&mut ws));


    loop {
        let mut input = String::new();
        print!("Message: ");

        io::stdout().flush().unwrap();
        io::stdin().read_line(&mut input).unwrap();

        let message = input.trim();

        let client = reqwest::Client::new();
        let res = client
            .post(&url)
            .json(&json!({ "msg": message }))
            .send()
            .await
            .expect("Connection Error (2)");

        let key = res.headers().get("key").unwrap().to_str().unwrap();

        ws.send(Message::Text(
            serde_json::to_string(&json!({ "key": key })).unwrap(),
        )).await.expect("Failed to send message");
    }
}

async fn msg_handle(ws: &mut tungstenite::WebSocketStream<tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>> ) {
    while let Some(Ok(message)) = ws.next().await {
        if let Ok(text) = message.to_text() {
            let parse: serde_json::Value = serde_json::from_str(text).unwrap();
            let id = parse["id"].as_u64().unwrap();
            let msg = parse["msg"].as_str().unwrap();

            println!("[{}]: {}", id, msg);
        }
    }

    println!("Connection closed");
    std::process::exit(0);
}