using Microsoft.Extensions.Options;
using SenseNet.Client;
using SenseNetAuth.Models;
using SenseNetAuth.Models.Constants;
using SenseNetAuth.Models.Options;
using System.DirectoryServices.AccountManagement;

namespace SenseNetAuth.Services
{
    public class UserService : IUserService
    {
        private readonly IRepositoryCollection _repositoryCollection;
        private readonly RegistrationSettings _registrationSettings;
        private readonly ADSettings _adsettingsOptions;

        public UserService(
            IRepositoryCollection repositoryCollection,
            IOptions<RegistrationSettings> registrationOptions,
            IOptions<ADSettings> adsettingsOptions
        )
        {
            _repositoryCollection = repositoryCollection;
            _registrationSettings = registrationOptions.Value;
            _adsettingsOptions = adsettingsOptions.Value;
        }

        public async Task<User?> GetUserByUserIdAsync(int userId, CancellationToken cancel)
        {
            var repo = await GetRepositoryAsync(cancel).ConfigureAwait(false);

            var query = new QueryContentRequest
            {
                ContentQuery = $"Id: {userId}",
            };

            return (await repo.QueryAsync<User>(query, cancel)
                .ConfigureAwait(false))
                .FirstOrDefault();
        }

        public async Task<int?> ValidateCredentialsAsync(string username, string password, CancellationToken cancel)
        {
            var repo = await GetRepositoryAsync(cancel);

            bool adEnabled = _adsettingsOptions.Enabled.ToLower() == "true";
            string adDomain = _adsettingsOptions.Domain.ToLower();
            if (!string.IsNullOrWhiteSpace(username) && adEnabled && !string.IsNullOrEmpty(adDomain) && username.ToLower().StartsWith(adDomain + "\\"))
            {
                var userHelper = username;
                if (!username.Contains("\\")) {
                    userHelper = adDomain + "\\" + username;
                }
                
                var query = new QueryContentRequest
                {
                    ContentQuery = $"+InTree:'/Root/IMS' +TypeIs:User +LoginName:{userHelper}",
                };
                var results = await repo.QueryAsync<User>(query, cancel).ConfigureAwait(false);

                if (results != null && results.Count() > 0)
                {
                    try
                    {
                        User queriedUser = results.First();
                        bool isADAuth = await ActiveDirectoryAuthentication(userHelper, password);
                        if (isADAuth)
                        {
                            return queriedUser.Id;
                        }
                    }
                    catch(Exception ex)
                    {
                        return null;
                    }
                }
            }
            else
            {
                var request = new OperationRequest
                {
                    OperationName = "ValidateCredentials",
                    Path = "/Root",
                    PostData = new
                    {
                        username,
                        password
                    }
                };

                try
                {
                    var response = await repo.InvokeActionAsync<dynamic>(request, cancel);
                    return response.id;
                }
                catch
                {
                    return null;
                }
            }

            return null;
        }

        public async Task<MultiFactorInfoResponse?> GetMultiFactorAuthenticationInfoAsync(int userId, CancellationToken cancel)
        {
            var repo = await GetRepositoryAsync(cancel);

            var request = new OperationRequest
            {
                OperationName = "GetMultiFactorAuthenticationInfo",
                ContentId = userId,
            };

            try
            {
                return await repo.InvokeActionAsync<MultiFactorInfoResponse>(request, cancel);
            }
            catch
            {
                return null;
            }
        }

        public async Task<bool> ValidateTwoFactorCodeAsync(int userId, string twoFactorCode, CancellationToken cancel)
        {
            var repo = await GetRepositoryAsync(cancel);

            var request = new OperationRequest
            {
                OperationName = "ValidateTwoFactorCode",
                ContentId = userId,
                PostData = new
                {
                    twoFactorCode
                }
            };

            try
            {
                var response = await repo.InvokeActionAsync<dynamic>(request, cancel);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task<User?> GetUserByEmailAsync(string email, CancellationToken cancel)
        {
            var repo = await GetRepositoryAsync(cancel);
            var query = new QueryContentRequest
            {
                ContentQuery = $"TypeIs:{nameof(User)} AND Email:{email}",
            };

            return (await repo.QueryAsync<User>(query, cancel)
                .ConfigureAwait(false))
                .FirstOrDefault();
        }

        public async Task<User?> RegisterUserAsync(string email, string password, string fullName, CancellationToken cancel)
        {
            var user = await GetUserByEmailAsync(email, cancel).ConfigureAwait(false);
            if (user == null)
            {
                var repo = await GetRepositoryAsync(cancel).ConfigureAwait(false);

                var userContent = repo.CreateContent<User>(_registrationSettings.MainUserPath, nameof(User), email);
                userContent.Email = email;
                userContent.LoginName = email;
                userContent.Password = password;
                userContent.FullName = fullName;
                userContent.Enabled = true;

                await userContent.SaveAsync(cancel).ConfigureAwait(false);
                return userContent;
            }

            return null;
        }
        public async Task<bool> ChangePasswordAsync(int userId, string password, CancellationToken cancel)
        {
            var user = await GetUserByUserIdAsync(userId, cancel).ConfigureAwait(false);
            if (user != null)
            {
                user.Password = password;
                await user.SaveAsync(cancel);

                return true;
            }

            return false;
        }

        private Task<bool> ActiveDirectoryAuthentication(string username, string password)
        {
            bool resultBool = false;

            using (PrincipalContext principalContext = new(ContextType.Domain))
            {
                resultBool = principalContext.ValidateCredentials(username, password);
            }

            return Task.FromResult(resultBool);
        }

        private async Task<User?> GetUserByUserIdAsync(IRepository repo, int userId, CancellationToken cancel)
        {
            //var query = new QueryContentRequest
            //{
            //    ContentQuery = $"Id: {userId}",
            //};
            var results = await repo.LoadContentAsync<User>(userId, cancel)
                .ConfigureAwait(false);

            return results;
        }

        private async Task<IRepository> GetRepositoryAsync(CancellationToken cancel) =>
            await _repositoryCollection.GetRepositoryAsync(new RepositoryArgs { Name = Repositories.Default }, cancel);
    }
}
