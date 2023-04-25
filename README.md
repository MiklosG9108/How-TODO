# How-TODO Backend

## Create Solution

- ProjectName: Solution.WebApi
- SolutionName: Solution
- ASP.NET Core Web Api
        - Framework: .NET 6.0 / .NET 7.0
        - Authentication type: None
        - HTTPS
        - Use controllers
        - Enable OpenApi support
- Delete WeatherForecast.cs and Controllers/WeatherForecastController.cs
 


## Install and update Nuget Packages
**1. Microsoft.AspNetCore.Identity**
**2. Microsoft.AspNetCore.Identity.EntityFrameworkCore**
**3. Microsoft.EntityFrameworkCore.SqlServer**
**4. Microsoft.EntityFrameworkCore.Tools**
**5. Microsoft.AspNetCore.Authentication.JwtBearer**


## Make Models/***DbContext.cs
- Name your DbContext instead of ***
```cs
public class ***DbContext : IdentityUserContext<ApplicationUser>
{
    public ***DbContext(DbContextOptions<***DbContext> options) : base(options)
    {
    }

}
```
## Make Models/ApplicationUser.cs
```cs
public class ApplicationUser : IdentityUser
{
	//with additional app specific properties for Example:
    //[Required]
    //public string Goal { get; set; } = string.Empty;
}
```
## Write the connectionString for appsettings.json
```json
"ConnectionStrings": {
  "Default": "Server=localhost;Database=***;User Id=***;Password=***;TrustServerCertificate=True"
},
```
## Add the service to the Program.cs' container
```cs
string connectionString = builder.Configuration.GetConnectionString("Default") ?? throw new InvalidOperationException("No connectionString");
builder.Services.AddDbContext<***DbContext>(options => options.UseSqlServer(connectionString));
```
## Write into package manager console
**Add-Migration AddIdentityTables**

## Setup database before startup in Program.cs before app.Run
```cs
//...
using (var scope = app.Services.CreateScope())
using (var context = scope.ServiceProvider.GetRequiredService<***DbContext>())
{
    await context.Database.MigrateAsync();
}
//...
app.Run
```
#### Optional: if you're not using top-level statements, add to Main method: *async Task*

## Add services into Program.cs
- Don't forget to **rewrite your DbContext name**!
```cs
builder.Services.AddIdentityCore<ApplicationUser>(options => {
                    options.SignIn.RequireConfirmedAccount = false;
                    options.User.RequireUniqueEmail = true;
                    options.Password.RequireDigit = false;
                    options.Password.RequiredLength = 6;
                    options.Password.RequireNonAlphanumeric = false;
                    options.Password.RequireUppercase = false;
                    options.Password.RequireLowercase = false;
                })
                .AddEntityFrameworkStores<***DbContext>();
```	
## Make to Controllers/UsersController.cs
```cs
[Route("api/[controller]")]
[ApiController]
public class UsersController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;

    public UsersController(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }
}
```
## Make to Model/ViewModel/CreateUserForm.cs *and* UserDetails.cs
```cs
public class CreateUserForm
{
    [Required]
    public string UserName { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;

    [Required]
    public string Email { get; set; } = string.Empty;

    //with additional app specific properties for Example:
    //[Required]
    //public string Goal { get; set; } = string.Empty;
}
```
```cs
public class UserDetails
{
    public string UserName { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;

    //with additional app specific properties for Example:
    //public string Goal { get; set; } = string.Empty;
}
```
## Add at the end of UsersController
```cs
// POST: api/Users
[HttpPost]
public async Task<ActionResult<CreateUserForm>> PostUser(CreateUserForm user)
{
    if (!ModelState.IsValid)
    {
        return BadRequest(ModelState);
    }

    var result = await _userManager.CreateAsync(
        new ApplicationUser() { UserName = user.UserName, Email = user.Email /*, Goal = user.Goal*/},
        user.Password
    );

    if (!result.Succeeded)
    {
        return BadRequest(result.Errors);
    }

    user.Password = null!;
    return CreatedAtAction(nameof(GetUser), new { userName = user.UserName }, user);
}

// GET: api/Users/username
[HttpGet("{username}")]
public async Task<ActionResult<UserDetails>> GetUser(string username)
{
    ApplicationUser? user = await _userManager.FindByNameAsync(username);

    if (user == null)
    {
        return NotFound();
    }

    return new UserDetails
    {
        UserName = user.UserName ?? string.Empty,
        Email = user.Email ?? string.Empty,
		//Goal= user.Goal ?? string.Empty
    };
}
```
# Implement JWT Bearer Token authentication 

## Make to Model/ViewModel/AuthenticationRequest.cs
```cs
public class AuthenticationRequest
{
    [Required]
    public string UserName { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;
}
```
## Make to Model/ViewModel/AuthenticationResponse.cs
```cs
public class AuthenticationResponse
{
    public string? Token { get; set; }

    public DateTime Expiration { get; set; }
}
```
## Copy into appsettings.json
```json
"Jwt": {
  "Key": "this is the secret key for the jwt, it must be kept secure",
  "Issuer": "vehiclequotes.endpointdev.com",
  "Audience": "vehiclequotes.endpointdev.com"
}
```
## Make to Service/JwtService.cs
```cs
public class JwtService : ITokenCreationService
{
    private const int EXPIRATION_MINUTES = 30;

    private readonly IConfiguration _configuration;

    public JwtService(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public AuthenticationResponse CreateToken(IdentityUser user)
    {
        var expiration = DateTime.UtcNow.AddMinutes(EXPIRATION_MINUTES);

        var token = CreateJwtToken(
            CreateClaims(user),
            CreateSigningCredentials(),
            expiration
        );

        var tokenHandler = new JwtSecurityTokenHandler();

        return new AuthenticationResponse
        {
            Token = tokenHandler.WriteToken(token),
            Expiration = expiration
        };
    }

    private JwtSecurityToken CreateJwtToken(Claim[] claims, SigningCredentials credentials, DateTime expiration) =>
        new JwtSecurityToken(
            _configuration["Jwt:Issuer"],
            _configuration["Jwt:Audience"],
            claims,
            expires: expiration,
            signingCredentials: credentials
        );

    private Claim[] CreateClaims(IdentityUser user) =>
        new[] {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString()),
        new Claim(ClaimTypes.NameIdentifier, user.Id),
        new Claim(ClaimTypes.Name, user.UserName ?? string.Empty),
        new Claim(ClaimTypes.Email, user.Email ?? string.Empty)
        };

    private SigningCredentials CreateSigningCredentials() =>
        new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"])),SecurityAlgorithms.HmacSha256);
}
```
## Make to Service/ITokenCreationService.cs
```cs
public interface ITokenCreationService
{
    AuthenticationResponse CreateToken(IdentityUser user);
}
```
## Add to UsersController
```cs
private readonly ITokenCreationService _jwtService;
```
```cs
public UsersController(UserManager<ApplicationUser> userManager, ITokenCreationService jwtService)
    {
        _userManager = userManager;
        _jwtService = jwtService;
    }
```

## Program.cs before Add services to the container
```cs
builder.Services.AddScoped<ITokenCreationService, JwtService>();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options => {
                    options.TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidAudience = builder.Configuration["Jwt:Audience"],
                        ValidIssuer = builder.Configuration["Jwt:Issuer"],
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"] ?? string.Empty))
                    };
                });
```
## Add at the end of UsersController
```
// POST: api/Users/BearerToken
[HttpPost("BearerToken")]
public async Task<ActionResult<AuthenticationResponse>> CreateBearerToken(AuthenticationRequest request)
{
    if (!ModelState.IsValid)
    {
        return BadRequest("Bad credentials");
    }

    var user = await _userManager.FindByNameAsync(request.UserName);

    if (user == null)
    {
        return BadRequest("Bad credentials");
    }

    var isPasswordValid = await _userManager.CheckPasswordAsync(user, request.Password);

    if (!isPasswordValid)
    {
        return BadRequest("Bad credentials");
    }

    var token = _jwtService.CreateToken(user);

    return Ok(token);
}
```
## Program.cs before app.UseAuthorization();
```cs
app.UseAuthentication();
```

# Extensions

## Add Extensions/ClaimsPrincipalExtensions.cs
```cs
internal static class ClaimsPrincipalExtensions
{
    public static string GetCurrentUserId(this ClaimsPrincipal user)
    {
        ArgumentNullException.ThrowIfNull(user);
        return user.FindFirstValue(ClaimTypes.NameIdentifier) ?? throw new InvalidOperationException("Current user Id is null");
    }
}
```
### Don't forget to start your Container!

# Roles
## Add to ITokenCreationService.cs
```cs
public AuthenticationResponse CreateToken(IdentityUser user, IList<string> roles)
    {
        var expiration = DateTime.UtcNow.AddMinutes(EXPIRATION_MINUTES);

        var token = CreateJwtToken(
            CreateClaims(user, roles),
            CreateSigningCredentials(),
            expiration
        );
```

## Add to JWTService.cs
```cs
public AuthenticationResponse CreateToken(IdentityUser user, IList<string> roles)
private Claim[] CreateClaims(IdentityUser user, IList<string> roles) =>
.Union(roles.Select(role => new Claim(ClaimTypes.Role, role)))
        .ToArray();
```
## Add to Program.cs' IdentityCore options:
```cs
.AddRoles<IdentityRole>()
```
### It will be look like this with the previous sign-in options:
```cs
builder.Services.AddIdentityCore<ApplicationUser>(options =>
{
    options.SignIn.RequireConfirmedAccount = false;
    options.User.RequireUniqueEmail = true;
    options.Password.RequireDigit = false;
    options.Password.RequiredLength = 6;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireLowercase = false;
})
.AddRoles<IdentityRole>()
```
## Add into Program.cs before app.Run():
```cs
using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var roleExist = await roleManager.RoleExistsAsync("Admin");
    if (!roleExist)
    {
        _ = await roleManager.CreateAsync(new IdentityRole("Admin"));
    }
}
```
## Change UserController in the PostUser() method from this:
```cs
var result = await _userManager.CreateAsync(
            new ApplicationUser() { UserName = user.UserName, Email = user.Email /*, Goal = user.Goal*/},
            user.Password
        );
```
### to this:
```cs
ApplicationUser user = new()
        {
            UserName = userForm.UserName,
            Email = userForm.Email,
            //Goal = userForm.Goal.Trim()
        };
        var result = await _userManager.CreateAsync(
            user,
            userForm.Password
        );
```
## Add to before UserController's PostUser() method's last return:
```cs
IdentityResult identityResult = await _userManager.AddToRoleAsync(user, role: "Admin");

if (!identityResult.Succeeded)
{
    throw new Exception("Failed to add user to role");
}
```

## Add to before CreateBearerToken's last return:
```cs
IList<string> roles = await _userManager.GetRolesAsync(user);
var token = _jwtService.CreateToken(user,roles);
```

