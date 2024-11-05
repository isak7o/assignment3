import os
import sys
import pytest
from flask import Flask

# Insert the app directory into the system path for module discovery
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import app

# Fixture to provide a test client for the application
@pytest.fixture
def test_client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

# Test the root URL
def test_homepage(test_client):
    response = test_client.get('/')
    assert response.status_code == 200, "Root URL did not return 200 OK"

# Test the public URL
def test_public_endpoint(test_client):
    response = test_client.get('/public/')
    assert response.status_code == 200, "Public URL did not return 200 OK"

# Test the private URL
def test_private_endpoint(test_client):
    response = test_client.get('/private/')
    assert response.status_code == 401, "Private URL did not return 401 Unauthorized"

# Test the admin URL
def test_admin_endpoint(test_client):
    response = test_client.get('/admin/')
    assert response.status_code == 401, "Admin URL did not return 401 Unauthorized"

# Add more test functions for other URLs or endpoints as needed
def test_not_found_endpoint(test_client):
    response = test_client.get('/nonexistent/')
    assert response.status_code == 404, "Nonexistent URL did not return 404 Not Found"

if __name__ == '__main__':
    # Execute the tests directly by running this script
    pytest.main()
