using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using FlightBooking5.Data;
using FlightBooking5.Models;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Authorization;

namespace FlightBooking5.Controllers
{
    public class ImageAdsController : Controller
    {
        private readonly FlightBooking5Context _context;
        private readonly IWebHostEnvironment _webHostEnvironment;

        public ImageAdsController(FlightBooking5Context context, IWebHostEnvironment webHostEnvironment)
        {
            _context = context;
            _webHostEnvironment = webHostEnvironment;
        }

        // GET: ImageAds
        [Authorize(Roles = "Admin Manager,Marketing")]
        public async Task<IActionResult> Index()
        {
                  return _context.ImageAd != null ? 
                              View(await _context.ImageAd.ToListAsync()) :
                              Problem("Entity set 'FlightBooking5Context.ImageAd'  is null.");
        }
        [Authorize(Roles = "Admin Manager,Marketing")]
        // GET: ImageAds/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null || _context.ImageAd == null)
            {
                return NotFound();
            }

            var imageAd = await _context.ImageAd
                .FirstOrDefaultAsync(m => m.ImageId == id);
            if (imageAd == null)
            {
                return NotFound();
            }

            return View(imageAd);
        }
        [Authorize(Roles = "Admin Manager,Marketing")]
        // GET: ImageAds/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: ImageAds/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(ImageAd imageAd)
        {
            if (imageAd.Photo != null)
            {
                string uploadsFolder = Path.Combine(_webHostEnvironment.WebRootPath, "img");

                // Tạo tên file duy nhất bằng cách kết hợp tên file gốc với một số ngẫu nhiên
                string uniqueFileName = Guid.NewGuid().ToString() + "_" + imageAd.Photo.FileName;

                // Kết hợp đường dẫn thư mục và tên file để có đường dẫn lưu file
                string filePath = Path.Combine(uploadsFolder, uniqueFileName);

                // Lưu file vào đường dẫn được chỉ định
                using (var fileStream = new FileStream(filePath, FileMode.Create))
                {
                    imageAd.Photo.CopyTo(fileStream);
                }
                imageAd.PhotoPath = "/img/" + uniqueFileName;
                imageAd.PhotoName = uniqueFileName;
                var entity = new ImageAd
                {
                    Title = imageAd.Title,
                    Content = imageAd.Content,
                    PhotoPath = imageAd.PhotoPath,
                    PhotoName = imageAd.PhotoName
                };
                _context.Add(entity);
                await _context.SaveChangesAsync();
                
                return RedirectToAction("Ads", "Admin");
            }
            return View(imageAd);
        }
        [Authorize(Roles = "Admin Manager,Marketing")]
        // GET: ImageAds/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null || _context.ImageAd == null)
            {
                return NotFound();
            }

            var imageAd = await _context.ImageAd.FindAsync(id);
            if (imageAd == null)
            {
                return NotFound();
            }
            return View(imageAd);
        }

        // POST: ImageAds/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("ImageId,Title,Content,PhotoPath,PhotoName")] ImageAd imageAd)
        {
            if (id != imageAd.ImageId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(imageAd);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!ImageAdExists(imageAd.ImageId))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction("Ads", "Admin");
            }
            return View(imageAd);
        }
        [Authorize(Roles = "Admin Manager,Marketing")]
        // GET: ImageAds/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null || _context.ImageAd == null)
            {
                return NotFound();
            }

            var imageAd = await _context.ImageAd
                .FirstOrDefaultAsync(m => m.ImageId == id);
            if (imageAd == null)
            {
                return NotFound();
            }

            return View(imageAd);
        }

        // POST: ImageAds/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            if (_context.ImageAd == null)
            {
                return Problem("Entity set 'FlightBooking5Context.ImageAd'  is null.");
            }
            var imageAd = await _context.ImageAd.FindAsync(id);
            if (imageAd != null)
            {
                _context.ImageAd.Remove(imageAd);
            }
            
            await _context.SaveChangesAsync();
            return RedirectToAction("Ads", "Admin");
        }

        private bool ImageAdExists(int id)
        {
          return (_context.ImageAd?.Any(e => e.ImageId == id)).GetValueOrDefault();
        }
    }
}
