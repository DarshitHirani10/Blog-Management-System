# 📝 Blog Management System

A secure and feature-rich **Flask-based Blog Management System** that allows users to register, create and manage blogs, interact with others via likes, comments, and follows. Built with Python Flask, HTML/CSS (Bootstrap), and SQLite with SQLAlchemy ORM.

## 🚀 Features

### ✅ User Authentication
- **Secure Registration** with **Email OTP Verification**
- **Login with Sessions** for secure user access
- Password hashing for safe storage (using Werkzeug)

### 📝 Blog Management
- Create, Read, Update, Delete (CRUD) blogs
- Only the author can edit or delete their blogs

### ❤️ Social Features
- Like blogs written by other users
- Follow and unfollow other users
- Comment on blog posts

### 👤 User Profiles
- View other users' profiles
- See their blogs, followers, and who they're following

---

## 🛠️ Tech Stack

- **Backend**: Flask, Flask-Login, Flask-Mail
- **Frontend**: HTML, CSS, Bootstrap, Jinja2 Templates
- **Database**: SQLite with SQLAlchemy ORM

---


## ⚙️ Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/DarshitHirani10/Blog-Management-System.git
cd blog-management-system
```

### 2. Create and Activate Virtual Environment
```bash
python -m venv venv

# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Set Up Environment Variables
```bash
Create a .env file in the root directory and add the following:
SECRET_KEY=your-secret-key
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
```

### 5. Run the Flask App
```bash
flask run  or 
python app.py run
```