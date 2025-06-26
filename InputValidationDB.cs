using System;
using System.Data;
using System.Data.SqlClient; // Assuming SQL Server for ADO.NET example
using System.Text.RegularExpressions;
using BCrypt.Net; // For password hashing, install via NuGet: Install-Package BCrypt.Net-Core

namespace SafeVault.Security
{
    // Class for input sanitization to prevent XSS and other injection attacks
    public static class InputSanitizer
    {
        /// <summary>
        /// Sanitizes a string input by removing potentially malicious HTML/script tags.
        /// Primarily used for preventing XSS attacks.
        /// </summary>
        /// <param name="input">The raw string input from the user.</param>
        /// <returns>A sanitized string.</returns>
        public static string SanitizeHtml(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return input;
            }

            // A more robust HTML sanitizer would use a dedicated library like AntiXSS or HtmlSanitizer.
            // For demonstration, this regex removes common script tags and event handlers.
            // WARNING: Simple regex is NOT a foolproof solution for XSS.
            // ALWAYS prefer dedicated HTML sanitization libraries in production.
            string sanitized = Regex.Replace(input, @"<script.*?</script>", "", RegexOptions.IgnoreCase | RegexOptions.Singleline);
            sanitized = Regex.Replace(sanitized, @"javascript:", "", RegexOptions.IgnoreCase);
            sanitized = Regex.Replace(sanitized, @"on\w+=\s*""[^""]*""", "", RegexOptions.IgnoreCase); // Remove event handlers

            // Basic HTML encoding for remaining potentially problematic characters
            sanitized = System.Net.WebUtility.HtmlEncode(sanitized);

            return sanitized;
        }

        /// <summary>
        /// Validates if an email address is in a valid format.
        /// </summary>
        /// <param name="email">The email string to validate.</param>
        /// <returns>True if the email is valid, false otherwise.</returns>
        public static bool IsValidEmail(string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                return false;
            }
            // Use a comprehensive regex for email validation
            // This regex is a simplified example; a more robust one exists for RFC-compliant validation.
            string emailPattern = @"^[^@\s]+@[^@\s]+\.[^@\s]+$";
            return Regex.IsMatch(email, emailPattern, RegexOptions.IgnoreCase);
        }

        /// <summary>
        /// Validates a username for allowed characters and length.
        /// </summary>
        /// <param name="username">The username string to validate.</param>
        /// <returns>True if the username is valid, false otherwise.</returns>
        public static bool IsValidUsername(string username)
        {
            if (string.IsNullOrEmpty(username) || username.Length < 3 || username.Length > 50)
            {
                return false;
            }
            // Allow alphanumeric, underscores, and hyphens
            string usernamePattern = @"^[a-zA-Z0-9_-]+$";
            return Regex.IsMatch(username, usernamePattern);
        }
    }

    // Class for secure database operations using parameterized queries
    public class UserRepository
    {
        private readonly string _connectionString;

        public UserRepository(string connectionString)
        {
            _connectionString = connectionString;
        }

        /// <summary>
        /// Retrieves user information securely using a parameterized query.
        /// This method demonstrates preventing SQL Injection.
        /// </summary>
        /// <param name="username">The username to search for.</param>
        /// <returns>A DataTable containing user info if found, null otherwise.</returns>
        public DataTable GetUserByUsername(string username)
        {
            // The SQL query uses a parameter placeholder (@Username) instead of direct string concatenation.
            // This is the primary defense against SQL Injection.
            string sqlQuery = "SELECT UserID, Username, Email, PasswordHash FROM Users WHERE Username = @Username";

            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                using (SqlCommand command = new SqlCommand(sqlQuery, connection))
                {
                    // Add the parameter and its value. The database engine will treat 'username' as a literal value.
                    command.Parameters.AddWithValue("@Username", username);

                    try
                    {
                        connection.Open();
                        SqlDataAdapter adapter = new SqlDataAdapter(command);
                        DataTable dataTable = new DataTable();
                        adapter.Fill(dataTable);
                        return dataTable;
                    }
                    catch (SqlException ex)
                    {
                        Console.WriteLine($"Database error: {ex.Message}");
                        // Log the exception details for debugging
                        return null;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"An unexpected error occurred: {ex.Message}");
                        return null;
                    }
                }
            }
        }

        /// <summary>
        /// Inserts a new user securely, hashing the password and using parameterized queries.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="email">The email.</param>
        /// <param name="password">The plain-text password.</param>
        /// <returns>True if user was added successfully, false otherwise.</returns>
        public bool AddUser(string username, string email, string password)
        {
            // Hash the password before storing it
            string hashedPassword = BCrypt.Net.BCrypt.HashPassword(password);

            string sqlQuery = "INSERT INTO Users (Username, Email, PasswordHash) VALUES (@Username, @Email, @PasswordHash)";

            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                using (SqlCommand command = new SqlCommand(sqlQuery, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    command.Parameters.AddWithValue("@Email", email);
                    command.Parameters.AddWithValue("@PasswordHash", hashedPassword);

                    try
                    {
                        connection.Open();
                        int rowsAffected = command.ExecuteNonQuery();
                        return rowsAffected > 0;
                    }
                    catch (SqlException ex)
                    {
                        // Handle specific SQL errors, e.g., unique constraint violation
                        if (ex.Number == 2627 || ex.Number == 2601) // Unique constraint violation error numbers
                        {
                            Console.WriteLine($"Error: Username or Email already exists. {ex.Message}");
                        }
                        else
                        {
                            Console.WriteLine($"Database error during user addition: {ex.Message}");
                        }
                        return false;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"An unexpected error occurred during user addition: {ex.Message}");
                        return false;
                    }
                }
            }
        }
    }
}
