using System.ComponentModel.DataAnnotations;

public class UserCreateViewModel
{
    [Required] public string FirstName { get; set; } = "";
    [Required, EmailAddress] public string Email { get; set; } = "";
    [Required, DataType(DataType.Password)] public string Password { get; set; } = "";
}
