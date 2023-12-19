using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ucak.Entities
{
    [Table("Users")]
    public class User
    {
        [Key]
        public Guid Id { get; set; }

        


        [Required]
        [StringLength(30)]
        public string Username { get; set; }


        [StringLength(50)]
        public string? FullName { get; set; } = null;

        [Required]
        [StringLength(100)]
        public string Password { get; set; }
        public bool Loked { get; set; } =false;
        public DateTime CreateAt { get; set; } = DateTime.Now;

        [Required]
        [StringLength(50)]
        public string Role { get; set; } = "user";
    }
}
