import unittest
from app import app
from db import init_db, get_db

class TestClassmateHub(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        init_db()

    def test_login_and_account_flow(self):
        # 1. Access homepage without cookie -> login form
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Log In", response.data)

        # 2. Login with invalid credentials
        response = self.client.post("/login", data={"username": "arjun", "password": "wrongpassword"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"didn't match", response.data)

        # 3. Login with valid credentials
        response = self.client.post("/login", data={"username": "arjun", "password": "Football123"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Hi, Arjun!", response.data)

        # 4. Set encrypted file payload (asymmetric RSA + AES key)
        response = self.client.post("/set-message", data={
            "ciphertext": "dGVzdF9jaXBoZXI=",
            "iv": "dGVzdF9pdg==",
            "encrypted_key": "dGVzdF9rZXk=",
            "filename": "test_file.txt"
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"data-ciphertext=\"dGVzdF9jaXBoZXI=\"", response.data)
        self.assertIn(b"data-encrypted-key=\"dGVzdF9rZXk=\"", response.data)
        self.assertIn(b"test_file.txt", response.data)

        # 5. Change password
        response = self.client.post("/change-password", data={"password": "NewFootballPass123"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)

        # Verify password in DB
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM accounts WHERE username = 'arjun'")
        row = cursor.fetchone()
        conn.close()
        self.assertEqual(row["password"], "NewFootballPass123")

        # 6. Logout
        response = self.client.get("/logout", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Log In", response.data)

    def test_static_files(self):
        response = self.client.get("/public/style.css")
        self.assertEqual(response.status_code, 200)
        response_crypto = self.client.get("/public/crypto.js")
        self.assertEqual(response_crypto.status_code, 200)

if __name__ == "__main__":
    unittest.main()
