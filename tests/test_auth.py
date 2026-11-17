def register(client, username="alice", password="correct-horse-battery"):
    return client.post("/register", json={"username": username, "password": password})

def login(client, username="alice", password="correct-horse-battery"):
    return client.post("/login", json={"username": username, "password": password})

def test_register_and_login(client):
    response = register(client)
    assert response.status_code == 201
    assert response.json()["user"]["role"] == "user"
    logged = login(client)
    assert logged.status_code == 200
    assert logged.json()["token_type"] == "bearer"

def test_duplicate_username_case_insensitive(client):
    assert register(client, "Alice").status_code == 201
    assert register(client, "ALICE").status_code == 409

def test_role_injection_rejected(client):
    response = client.post("/register", json={"username": "mallory", "password": "correct-horse-battery", "role": "admin"})
    assert response.status_code == 422

def test_logout_revokes_token(client):
    register(client)
    token = login(client).json()["access_token"]
    response = client.post("/logout", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 204
    assert client.post("/records", json={"title": "x", "body": "y"}, headers={"Authorization": f"Bearer {token}"}).status_code == 401
