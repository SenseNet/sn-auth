using SenseNet.Client;
using SenseNetAuth.Models;

namespace SenseNetAuth.Services;

public interface IUserService
{
    public Task<int?> ValidateCredentialsAsync(string username, string password, CancellationToken cancel);
    public Task<User?> GetUserByUserIdAsync(int userId, CancellationToken cancel);
    public Task<User?> GetUserByEmailAsync(string email, CancellationToken cancel);
    public Task<User?> RegisterUserAsync(string email, string password, string fullName, CancellationToken cancel);
    public Task<bool> ChangePasswordAsync(int userId, string password, CancellationToken cancel);
    public Task<MultiFactorInfoResponse?> GetMultiFactorAuthenticationInfoAsync(int userId, CancellationToken cancel);
    public Task<bool> ValidateTwoFactorCodeAsync(int userId, string twoFactorCode, CancellationToken cancel);
}
