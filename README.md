# BookShelf Management System

A modern, responsive web application for managing a shared book collection with user authentication and role-based access control.

## Features

### Public Features

- **Browse Books**: View all books in the collection with search and filtering
- **Search & Filter**: Find books by title, author, genre, or availability status
- **User Registration**: Create new accounts to contribute to the collection

### User Features

- **Personal Library**: View books you've added to the collection
- **Add Books**: Contribute new books with detailed information
- **Profile Management**: Update your account information
- **Book Management**: Track book availability and details

### Admin Features

- **User Management**: View and manage all registered users
- **Book Administration**: Full access to all books in the system
- **System Overview**: Administrative dashboard for complete system control

## Technology Stack

- **Frontend**: Pure HTML5, CSS3, JavaScript (ES6+)
- **Styling**: Custom CSS with glassmorphism design and responsive layout
- **Authentication**: JWT token-based authentication with refresh tokens
- **API Integration**: RESTful API communication with automatic token refresh

## Getting Started

1. Open `index.html` in a web browser
2. Browse books without authentication, or
3. Register/login to access personal features
4. Admin users have additional management capabilities

## API Endpoints

The application expects the following API structure:

- `POST /api/v1/auth/login/` - User authentication
- `POST /api/v1/auth/register/` - User registration
- `GET /api/v1/auth/profile/` - Get/update user profile
- `GET /api/v1/books/` - List all books (with search/filter)
- `POST /api/v1/books/add/` - Add new book
- `GET /api/v1/books/my-books/` - Get user's books
- `GET /api/v1/auth/admin/users/` - Admin: manage users
- `GET /api/v1/books/admin/all-books/` - Admin: manage all books

## Design Features

- **Modern UI**: Glassmorphism design with gradient backgrounds
- **Responsive**: Mobile-friendly layout that adapts to all screen sizes
- **Smooth Interactions**: Hover effects and transitions for better UX
- **Accessible**: Semantic HTML and proper form validation
- **Secure**: Token-based authentication with automatic refresh

## User Roles

- **Public**: Can browse and search books
- **Registered Users**: Can add books and manage their profile
- **Administrators**: Full system access and user management

## Browser Compatibility

Compatible with all modern browsers supporting ES6+ features including:

- Chrome 60+
- Firefox 55+
- Safari 12+
- Edge 79+
