namespace FlightBooking5.Models
{
	public class PaymentDetails
	{
		public int Id { get; set; }
		public string PaymentId { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string ?PhoneNumber { get; set; }
        public String Amount { get; set; }
		public string Status { get; set; }
		public DateTime PaymentDate { get; set; }
	}
}
