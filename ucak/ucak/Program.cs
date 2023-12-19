using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System.Reflection;
using ucak.Entities;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews().AddRazorRuntimeCompilation();
builder.Services.AddAutoMapper(Assembly.GetExecutingAssembly());// miras almiş class ları iceren dosyaları AutoMapper ile okumak için
builder.Services.AddDbContext<DatabaseContext>(opts =>
{
    opts.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
    //opts.UseLazyLoadingProxies();
});

builder.Services
              .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
              .AddCookie(opts =>
              {
                  opts.Cookie.Name = ".ucak.auth"; // cookie ismi
                  opts.ExpireTimeSpan = TimeSpan.FromDays(7);// 7 gün sonra veriler silinir cookies'den
                  opts.SlidingExpiration = false;// kullanıcı giris yaptıkca expire süresinin uzamasını engleller
                  opts.LoginPath = "/Account/Login"; // login sayfasına yönlendirir
                  opts.LogoutPath = "/Account/Logout"; // logout sayfasına yönlendirir
                  opts.AccessDeniedPath = "/Home/AccessDenied"; // yetkisi olmadıdında gidecegi sayfa
              });




var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
