using AutoMapper;
using ucak.Entities;
using ucak.Models;
using ucak.Entities;
namespace ucak
{
    public class AutoMapperConfig:Profile
    {
        public AutoMapperConfig()
        {
            CreateMap<User,UserModel>().ReverseMap();// User classını UserModel classına cevir ve bunu tersini de yap
            CreateMap<User, CreateUserModel>().ReverseMap();
            CreateMap<User, EditUserModel>().ReverseMap();

        }
    }
}
