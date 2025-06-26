using NUnit.Framework;
using SafeVault.Security;
using System.Data; // For DataTable
using Moq; // For mocking dependencies

namespace SafeVault.Tests
{
    [TestFixture]
    public class TestAuthenticationAndAuthorization
    {
        private Mock<UserRepository> _mockUserRepository;
        private AuthService _authService;
        private AuthorizationService _authZService;
        private AdminDashboard _adminDashboard;

        // Sample data for mocking
        private const string TEST_VALID_USERNAME = "testuser";
        private const string TEST_VALID_PASSWORD = "password123";
        private string TEST_VALID_PASSWORD_HASH; // Will be generated in Setup

        private const string ADMIN_USERNAME = "adminuser";
        private const string ADMIN_PASSWORD = "adminpass";
        private string ADMIN_PASSWORD_HASH; // Will be generated in Setup

        [SetUp]
        public void Setup()
        {
            // Initialize mocks for a clean test state per test method
            _mockUserRepository = new Mock<UserRepository>("dummy_connection_string"); // Connection string is irrelevant for mock

            _authService = new AuthService(_mockUserRepository.Object);
            _authZService = new AuthorizationService();
            _adminDashboard = new AdminDashboard(_authZService);

            // Pre-calculate hashes for test users
            TEST_VALID_PASSWORD_HASH = BCrypt.Net.BCrypt.HashPassword(TEST_VALID_PASSWORD);
            ADMIN_PASSWORD_HASH = BCrypt.Net.BCrypt.HashPassword(ADMIN_PASSWORD);

            // Configure mock to return specific user data for authentication tests
            SetupMockUser(TEST_VALID_USERNAME, TEST_VALID_PASSWORD_HASH, 1, "test@example.com");
            SetupMockUser(ADMIN_USERNAME, ADMIN_PASSWORD_HASH, 2, "admin@example.com");
        }

        private void SetupMockUser(string username, string passwordHash, int userId, string email)
        {
            DataTable dt = new DataTable();
            dt.Columns.Add("UserID", typeof(int));
            dt.Columns.Add("Username", typeof(string));
            dt.Columns.Add("Email", typeof(string));
            dt.Columns.Add("PasswordHash", typeof(string));

            dt.Rows.Add(userId, username, email, passwordHash);

            _mockUserRepository.Setup(repo => repo.GetUserByUsername(username)).Returns(dt);
        }

        // --- Authentication Tests ---

        [Test]
        public void AuthenticateUser_ValidCredentials_ReturnsUser()
        {
            User user = _authService.AuthenticateUser(TEST_VALID_USERNAME, TEST_VALID_PASSWORD);
            Assert.That(user, Is.Not.Null);
            Assert.That(user.Username, Is.EqualTo(TEST_VALID_USERNAME));
            Assert.That(user.Roles, Contains.Item("user"));
            Assert.That(user.Roles, Does.Not.Contain("admin"));
        }

        [Test]
        public void AuthenticateUser_InvalidPassword_ReturnsNull()
        {
            User user = _authService.AuthenticateUser(TEST_VALID_USERNAME, "wrongpassword");
            Assert.That(user, Is.Null);
        }

        [Test]
        public void AuthenticateUser_UserNotFound_ReturnsNull()
        {
            _mockUserRepository.Setup(repo => repo.GetUserByUsername("nonexistentuser")).Returns((DataTable)null); // Or empty DataTable

            User user = _authService.AuthenticateUser("nonexistentuser", "anypassword");
            Assert.That(user, Is.Null);
        }

        [Test]
        public void AuthenticateUser_AdminValidCredentials_ReturnsAdminUser()
        {
            User adminUser = _authService.AuthenticateUser(ADMIN_USERNAME, ADMIN_PASSWORD);
            Assert.That(adminUser, Is.Not.Null);
            Assert.That(adminUser.Username, Is.EqualTo(ADMIN_USERNAME));
            Assert.That(adminUser.Roles, Contains.Item("admin"));
            Assert.That(adminUser.Roles, Contains.Item("user"));
        }

        // --- Authorization (RBAC) Tests ---

        [Test]
        public void HasRole_UserHasRole_ReturnsTrue()
        {
            User user = new User { Username = "test", Roles = { "user", "editor" } };
            Assert.IsTrue(_authZService.HasRole(user, "user"));
            Assert.IsTrue(_authZService.HasRole(user, "editor"));
        }

        [Test]
        public void HasRole_UserDoesNotHaveRole_ReturnsFalse()
        {
            User user = new User { Username = "test", Roles = { "user" } };
            Assert.IsFalse(_authZService.HasRole(user, "admin"));
        }

        [Test]
        public void HasRole_NullUser_ReturnsFalse()
        {
            Assert.IsFalse(_authZService.HasRole(null, "admin"));
        }

        [Test]
        public void Authorize_AdminAccess_GrantsAccess()
        {
            User adminUser = new User { Username = "adminuser", Roles = { "admin", "user" } };
            // Should not throw an exception
            Assert.DoesNotThrow(() => _authZService.Authorize(adminUser, "admin"));
        }

        [Test]
        public void Authorize_UserAccess_DeniesAdminAccess()
        {
            User regularUser = new User { Username = "regularuser", Roles = { "user" } };
            // Should throw an UnauthorizedAccessException
            Assert.Throws<UnauthorizedAccessException>(() => _authZService.Authorize(regularUser, "admin"));
        }

        [Test]
        public void AdminDashboard_AdminUser_CanView()
        {
            User adminUser = new User { Username = "adminuser", Roles = { "admin", "user" } };
            // Should execute without throwing an exception
            Assert.DoesNotThrow(() => _adminDashboard.ViewDashboard(adminUser));
        }

        [Test]
        public void AdminDashboard_RegularUser_CannotView()
        {
            User regularUser = new User { Username = "regularuser", Roles = { "user" } };
            // Should throw UnauthorizedAccessException
            Assert.Throws<UnauthorizedAccessException>(() => _adminDashboard.ViewDashboard(regularUser));
        }

        [Test]
        public void AdminDashboard_UnauthenticatedUser_CannotView()
        {
            // Null user simulates an unauthenticated request
            Assert.Throws<UnauthorizedAccessException>(() => _adminDashboard.ViewDashboard(null));
        }
    }
}
