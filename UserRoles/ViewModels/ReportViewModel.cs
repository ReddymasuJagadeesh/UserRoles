namespace UserRoles.ViewModels
{
    public class ReportViewModel
    {
        public int Id { get; set; }
        public string ApplicationUserId { get; set; } = string.Empty;
        public string? UserName { get; set; }         // email or username of the owner
        public string? FirstName { get; set; }        // from Users.FirstName (optional)
        public DateTime Date { get; set; }
        public string Task { get; set; } = string.Empty;
        public string? Note { get; set; }
        public string? ReportedTo { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}
