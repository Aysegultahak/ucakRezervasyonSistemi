using Microsoft.AspNetCore.Mvc;
using FlightBooking5.Models;
using PayPal.Api;
using FlightBooking5.Data;
using FlightBooking5.Infrastructure;

namespace FlightBooking5.Controllers
{
    public class PaymentController : Controller
    {
        private readonly string _clientId = "AcrXA9KMHUuNr-K_lplWhjv00epr5zxnCUgSzbkwnOxDGEdr--u8UvtlxWPFW8L1P0zK93ym8K44qV3R";
        private readonly string _clientSecret = "EBfWuDfcPiJMG87QE_CeWTeWPl84jPIXVlgg4eVRy3WT4927COzpt17seV5D0YpCv8W9PUGmXaUE8eNH";

		private readonly FlightBooking5Context _context;
        
        public PaymentController(FlightBooking5Context context)
		{
			_context = context;
		}
		[HttpPost]
        public IActionResult CreatePayment(string currency, decimal total)
        {
            var apiContext = PaypalService.GetAPIContext(_clientId, _clientSecret);

            var payment = new Payment
            {
                intent = "sale",
                payer = new Payer { payment_method = "paypal" },
                transactions = new List<Transaction>
        {
            new Transaction
            {
                amount = new Amount
                {
                    currency = currency,
                    total = total.ToString()
                },
                description = "Payment description"
            }
        },
                redirect_urls = new RedirectUrls
                {
                    return_url = Url.Action("ExecutePayment", "Payment", null, Request.Scheme),
                    cancel_url = Url.Action("Index", "Home", null, Request.Scheme)
                }
            };

            var createdPayment = payment.Create(apiContext);

            // Redirect the user to the PayPal payment page
            var redirectUrl = createdPayment.links.Find(l => l.rel.Equals("approval_url")).href;
            return Redirect(redirectUrl);
        }

        public IActionResult ExecutePayment(string paymentId, string token, string PayerID)
        {
            var apiContext = PaypalService.GetAPIContext(_clientId, _clientSecret);

            var paymentExecution = new PaymentExecution { payer_id = PayerID };
            var payment = new Payment { id = paymentId };

            var executedPayment = payment.Execute(apiContext, paymentExecution);

			// Xử lý kết quả thanh toán
			
			var paymentData = new PaymentDetails
			{
				PaymentId = paymentId,
                FirstName = executedPayment.payer.payer_info.first_name,
                LastName = executedPayment.payer.payer_info.last_name,
                Email = executedPayment.payer.payer_info.email,
                PhoneNumber = executedPayment.payer.payer_info.phone,
                Amount  = executedPayment.transactions.FirstOrDefault().amount.total,
				Status = executedPayment.state,
				PaymentDate = DateTime.Now,
               
            };
			// Lưu paymentData vào cơ sở dữ liệu
			_context.PaymentDetails.Add(paymentData);
			_context.SaveChanges();           
            return View("PaymentSuccess",paymentData);

           
        }
    }
}
