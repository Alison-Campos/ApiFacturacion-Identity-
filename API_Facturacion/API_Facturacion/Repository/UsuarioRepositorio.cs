using API_Facturacion.Data;
using API_Facturacion.Models;
using API_Facturacion.Models.Dtos;
using API_Facturacion.Repository.IRepository;
using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using XSystem.Security.Cryptography;

namespace API_Facturacion.Repository
{
    public class UsuarioRepositorio : IUsuarioRepositorio
    {
        private readonly Context db;
        private string claveSecreta;
        private readonly UserManager<AppUsuario> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IMapper _mapper;
        public UsuarioRepositorio(Context _db, IConfiguration configuration, 
            RoleManager<IdentityRole> roleManager, UserManager<AppUsuario> userManager, IMapper mapper )
        {
            db = _db;
            claveSecreta = configuration.GetValue<string>("ApiSettings:Secreta");
            _roleManager = roleManager;
            _userManager = userManager;
            _mapper = mapper;
        }
        public ICollection<AppUsuario> GetUsuarios()
        {
            return db.AppUsuario.OrderBy(u => u.UserName).ToList();
        }

        public AppUsuario GetUsuario(string usuarioId)
        {
             return db.AppUsuario.FirstOrDefault(u => u.Id == usuarioId);
            
        }

        public bool IsUniqueUser(string usuario)
        {
            var usuarioId = db.AppUsuario.FirstOrDefault(u => u.UserName == usuario);
            if (usuarioId == null)
            {
                return true;
            }
            return false;
        }
        public async Task<Usuario> Registro(UsuarioRegistroDto usuarioRegistroDto)
        {
            var passworEncriptado = obtenermd5(usuarioRegistroDto.Password);
            Usuario usuario = new Usuario()
            {
                Email = usuarioRegistroDto.Email,
                Password = passworEncriptado,
                Nombre = usuarioRegistroDto.Nombre,
                Role = usuarioRegistroDto.Role,
            };
            db.Add(usuario);
            await db.SaveChangesAsync();
            usuario.Password = passworEncriptado;
            return usuario;

        }
        public async Task<UsuarioLoginRespuestaDto> Login(UsuarioLoginDto usuarioLoginDto)
        {
            // Utilizar FirstOrDefaultAsync para operaciones asincrónicas en la base de datos
            var usuario = await db.AppUsuario.FirstOrDefaultAsync(
                u => u.UserName.ToLower() == usuarioLoginDto.Email.ToLower());

            bool isValid = await _userManager.CheckPasswordAsync(usuario, usuarioLoginDto.Password);
           
            if (usuario == null || isValid == false)
            {
                return new UsuarioLoginRespuestaDto
                {
                    Token = "",
                    Usuario = null
                };
            }
            var roles = await _userManager.GetRolesAsync(usuario);

            var manejarToken = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(claveSecreta);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, usuario.Email.ToString() ),
                    new Claim(ClaimTypes.Role, roles.FirstOrDefault() )
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = manejarToken.CreateToken(tokenDescriptor);

            UsuarioLoginRespuestaDto usuarioLoginRespuestaDto = new UsuarioLoginRespuestaDto
            {
                Token = manejarToken.WriteToken(token),
                Usuario = _mapper.Map<UsuarioDatosDto>(usuario)
            };
            return usuarioLoginRespuestaDto;
        }

        //Método para encriptar contraseña con MD5 se usa tanto en el Acceso como en el Registro
        public static string obtenermd5(string valor)
        {
            MD5CryptoServiceProvider x = new MD5CryptoServiceProvider();
            byte[] data = System.Text.Encoding.UTF8.GetBytes(valor);
            data = x.ComputeHash(data);
            string resp = "";
            for (int i = 0; i < data.Length; i++)
                resp += data[i].ToString("x2").ToLower();
            return resp;
        }
    }

}
