def test_fifth_failed_login_locks_account(client):
    client.post("/register", json={"username": "alice", "password": "correct-horse-battery"})
    for _ in range(4):
        assert client.post("/login", json={"username": "alice", "password": "wrong-password"}).status_code == 401
    assert client.post("/login", json={"username": "alice", "password": "wrong-password"}).status_code == 429
    assert client.post("/login", json={"username": "alice", "password": "correct-horse-battery"}).status_code == 429
