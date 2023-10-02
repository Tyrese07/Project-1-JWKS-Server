import unittest
import json
import sys
sys.path.append("C:/Users/palme/OneDrive/Desktop/Project 1 JWKS Server.py")

from .. import app

class TestApp(unittest.TestCase):

    def setUp(self):
        app.config['TESTING'] = True
        self.app = app.test_client()

    def tearDown(self):
        pass

    def test_successful_authentication(self):
        response = self.app.post('/auth', json={'username': 'userABC', 'password': 'password123'})
        self.assertEqual(response.status_code, 200)
        self.assertIn('token', response.json)

    def test_failed_authentication(self):
        response = self.app.post('/auth', json={'username': 'invalid', 'password': 'invalid'})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data.decode('utf-8'), 'Authentication failed')

    def test_jwks_endpoint(self):
        response = self.app.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        self.assertIn('keys', response.json)

   

if __name__ == '__main__':
    unittest.main()