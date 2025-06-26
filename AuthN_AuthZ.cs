using System;
using System.Data;
using System.Linq;
using System.Collections.Generic;
using BCrypt.Net; // For password hashing

namespace SafeVault.Security
{
    // Represents a user in the system
    public class User
    {
        public int UserID { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public string PasswordHash { get; set; }
        public List<string> Roles { get; set; } = new List<string>(); // e.g., "admin", "user"
    }

    // Service for user authentication
    public class AuthService
    {
        private readonly UserRepository _userRepository;

        public AuthService(UserRepository userRepository)
        {
            _userRepository = userRepository;
        }

        /// <summary>
        /// Authenticates a user by verifying their username and hashed password.
        /// </summary>
        /// <param name="username">The provided username.</param>
        /// <param name="plainTextPassword">The provided plain-text password.</param>
        /// <returns>The authenticated User object if successful, null otherwise.</returns>
        public User AuthenticateUser(string username, string plainTextPassword)
        {
            // 1. Retrieve user by username from the database
            DataTable userData = _userRepository.GetUserByUsername(username);

            if (userData == null || userData.Rows.Count == 0)
            {
                Console.WriteLine($"Authentication failed: User '{username}' not found.");
                return null; // User not found
            }

            // 2. Get the hashed password from the database
            DataRow userRow = userData.Rows[0];
            string storedPasswordHash = userRow["PasswordHash"].ToString();
            int userId = Convert.ToInt32(userRow["UserID"]);
            string email = userRow["Email"].ToString();

            // 3. Verify the provided plain-text password against the stored hash
            // BCrypt.Net.BCrypt.Verify handles the salt and hashing internally.
            if (BCrypt.Net.BCrypt.Verify(plainTextPassword, storedPasswordHash))
            {
                Console.WriteLine($"Authentication successful for user '{username}'.");
                // Authentication successful, now retrieve roles
                User authenticatedUser = new User
                {
                    UserID = userId,
                    Username = username,
                    Email = email
                };

                // Retrieve user roles (assuming UserRepository has a method for this)
                // For this example, let's assume a simplified role retrieval.
                // In a real app, you'd have a method in UserRepository like GetUserRoles(userId)
                // For now, hardcode some based on user ID for demonstration
                if (username.Equals("adminuser", StringComparison.OrdinalIgnoreCase))
                {
                    authenticatedUser.Roles.Add("admin");
                }
                authenticatedUser.Roles.Add("user"); // All authenticated users have 'user' role
                
                return authenticatedUser;
            }
            else
            {
                Console.WriteLine($"Authentication failed: Invalid password for user '{username}'.");
                return null; // Password mismatch
            }
        }
    }

    // Service for role-based authorization
    public class AuthorizationService
    {
        /// <summary>
        /// Checks if a user has a specific role.
        /// </summary>
        /// <param name="user">The User object.</param>
        /// <param name="requiredRole">The role name to check for.</param>
        /// <returns>True if the user has the required role, false otherwise.</returns>
        public bool HasRole(User user, string requiredRole)
        {
            if (user == null || user.Roles == null)
            {
                return false;
            }
            return user.Roles.Contains(requiredRole, StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Protects access to a feature, throwing an UnauthorizedAccessException if the user lacks the role.
        /// </summary>
        /// <param name="user">The user attempting access.</param>
        /// <param name="requiredRole">The role needed to access the feature.</param>
        /// <exception cref="UnauthorizedAccessException">Thrown if the user does not have the required role.</exception>
        public void Authorize(User user, string requiredRole)
        {
            if (!HasRole(user, requiredRole))
            {
                throw new UnauthorizedAccessException($"Access denied: User '{user?.Username ?? "Anonymous"}' does not have the '{requiredRole}' role.");
            }
            Console.WriteLine($"Access granted: User '{user.Username}' has the '{requiredRole}' role.");
        }
    }

    // Example of an Admin Dashboard controller/logic (simplified)
    public class AdminDashboard
    {
        private readonly AuthorizationService _authService;

        public AdminDashboard(AuthorizationService authService)
        {
            _authService = authService;
        }

        public void ViewDashboard(User currentUser)
        {
            try
            {
                _authService.Authorize(currentUser, "admin");
                Console.WriteLine("Admin Dashboard: Displaying sensitive administrative tools.");
                // Actual admin dashboard logic would go here
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}
