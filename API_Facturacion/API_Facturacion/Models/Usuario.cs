﻿using System.ComponentModel.DataAnnotations;

namespace API_Facturacion.Models
{
    public class Usuario
    {
        [Key] 
        public string IdUsuario { get; set; }
        public string Email { get; set; }
        public string Nombre { get; set; }
        public string Password { get; set; }
        public string Role { get; set; }
    }
}
