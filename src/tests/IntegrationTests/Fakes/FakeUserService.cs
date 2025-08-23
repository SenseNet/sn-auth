using Microsoft.Extensions.Logging;
using Moq;
using SenseNet.Client;
using SenseNetAuth.Models;
using SenseNetAuth.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IntegrationTests.Fakes
{
    internal class FakeUserService : IUserService
    {
        private TestRestCaller _restCaller;

        public FakeUserService()
        {
            _restCaller = new TestRestCaller("http://localhost:8080");
        }

        public Task<bool> ChangePasswordAsync(int userId, string password, CancellationToken cancel)
        {
            throw new NotImplementedException();
        }

        public Task<MultiFactorInfoResponse?> GetMultiFactorAuthenticationInfoAsync(int userId, CancellationToken cancel)
        {
            return Task.FromResult<MultiFactorInfoResponse?>(null);
        }

        public Task<User?> GetUserByEmailAsync(string email, CancellationToken cancel)
        {
            throw new NotImplementedException();
        }

        public Task<User?> GetUserByUserIdAsync(int userId, CancellationToken cancel)
        {
            return Task.FromResult<User?>(new User(_restCaller, Mock.Of<ILogger<Content>>())
            {

                Id = userId,
                Email = "test@test.com",
                FullName = "Test User",
                LoginName = "testuser"

            });
        }

        public Task<User?> RegisterUserAsync(string email, string password, string fullName, CancellationToken cancel)
        {
            throw new NotImplementedException();
        }

        public Task<int?> ValidateCredentialsAsync(string username, string password, CancellationToken cancel)
        {
            return Task.FromResult((int?)1);
        }

        public Task<bool> ValidateTwoFactorCodeAsync(int userId, string twoFactorCode, CancellationToken cancel)
        {
            throw new NotImplementedException();
        }
    }
}
