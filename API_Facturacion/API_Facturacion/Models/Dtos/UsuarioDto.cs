using System.ComponentModel.DataAnnotations;

namespace API_Facturacion.Models.Dtos
{
    public class UsuarioDatosDto
    {
        [Key]
        public String  Id { get; set; } 
        public string UserName { get; set; }
        public string Nombre { get; set; }
    }
}
