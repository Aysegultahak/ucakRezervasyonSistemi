namespace FlightBooking5.Models
{
    public class Cart
    {
        public List<CartLine>  Lines { get; set; }=new List<CartLine>();
        public void AddItem(Flight flight, int quantity)
        {
            CartLine? line = Lines
            .Where(f =>f.Flight.flightId==flight.flightId)
            .FirstOrDefault();
            if (line==null)
            {
                Lines.Add(new CartLine
                {
                    Flight = flight,
                    Quantity = quantity
                });
            }
            else
            {
                line.Quantity += quantity;
            }
        }
        public void RemoveLine(Flight flight) => Lines.RemoveAll(l=> l.Flight.flightId == flight.flightId);
        
        public decimal ComputeTotalValue() =>
           (decimal) Lines.Sum(e => e.Flight.Price * e.Quantity);
        public void Clear() => Lines.Clear();
    }
    public class CartLine
    {
        public int CartLineId { get; set; }
        public Flight Flight { get; set; }
        public int Quantity { get; set; }
    }

}
