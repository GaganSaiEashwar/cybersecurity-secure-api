def make_user(client, username):
    client.post("/register", json={"username": username, "password": "correct-horse-battery"})
    token = client.post("/login", json={"username": username, "password": "correct-horse-battery"}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_users_cannot_read_each_others_records(client):
    alice = make_user(client, "alice")
    bob = make_user(client, "bob")
    created = client.post("/records", json={"title": "Alice private", "body": "secret"}, headers=alice)
    record_id = created.json()["id"]
    denied = client.get(f"/records/{record_id}", headers=bob)
    assert denied.status_code == 404
    assert "secret" not in denied.text

def test_owner_can_read_own_record(client):
    alice = make_user(client, "alice")
    created = client.post("/records", json={"title": "private", "body": "note"}, headers=alice)
    assert client.get(f"/records/{created.json()['id']}", headers=alice).status_code == 200

def test_owner_id_spoofing_rejected(client):
    alice = make_user(client, "alice")
    response = client.post("/records", json={"title": "private", "body": "note", "owner_id": 999}, headers=alice)
    assert response.status_code == 422
