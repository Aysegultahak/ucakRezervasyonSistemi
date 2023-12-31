using PayPal.Api;
using System.Collections.Generic;

namespace FlightBooking5.Models
{
    public static class PaypalService
    {
        // Lấy access token từ PayPal API
        private static string GetAccessToken(string clientId, string clientSecret)
        {
            var config = new Dictionary<string, string>
            {
                { "mode", "sandbox" }, // Chế độ sandbox để kiểm thử, nếu bạn muốn triển khai thực tế, hãy sử dụng "live"
                { "clientId", clientId },
                { "clientSecret", clientSecret }
            };

            var accessToken = new OAuthTokenCredential(config).GetAccessToken();
            return accessToken;
        }

        // Khởi tạo APIContext
        public static APIContext GetAPIContext(string clientId, string clientSecret)
        {
            var accessToken = GetAccessToken(clientId, clientSecret);

            var apiContext = new APIContext(accessToken)
            {
                Config = new Dictionary<string, string>
                {
                    { "mode", "sandbox" } // Chế độ sandbox, tương tự như ở GetAccessToken
                }
            };

            return apiContext;
        }
    }
}
