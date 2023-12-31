
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
namespace FlightBooking5.Models
{
    public class ImageAd
    {
        [Key]
        public int ImageId { get; set; }
        public string Title { get; set; }
        public string Content { get; set; }
        [NotMapped]
        public IFormFile Photo { get; set; } // Thuộc tính để nhận file ảnh từ form
        public string PhotoPath { get; set; } // Đường dẫn của ảnh trong thư mục "wwwroot/img"
        public string PhotoName { get; set; } // Tên file ảnh
    }
}
