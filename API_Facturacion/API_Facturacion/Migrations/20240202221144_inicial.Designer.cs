﻿// <auto-generated />
using System;
using API_Facturacion.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

#nullable disable

namespace API_Facturacion.Migrations
{
    [DbContext(typeof(Context))]
    [Migration("20240202221144_inicial")]
    partial class inicial
    {
        /// <inheritdoc />
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "8.0.0")
                .HasAnnotation("Relational:MaxIdentifierLength", 128);

            SqlServerModelBuilderExtensions.UseIdentityColumns(modelBuilder);

            modelBuilder.Entity("API_Facturacion.Models.Cliente", b =>
                {
                    b.Property<Guid>("IdCliente")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uniqueidentifier");

                    b.Property<string>("Nombre")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("cedula")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("email")
                        .HasColumnType("nvarchar(max)");

                    b.HasKey("IdCliente");

                    b.ToTable("Clientes");
                });

            modelBuilder.Entity("API_Facturacion.Models.Factura", b =>
                {
                    b.Property<int>("numeroFactura")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<int>("numeroFactura"));

                    b.Property<DateTime>("fecha")
                        .HasColumnType("datetime2");

                    b.Property<Guid>("idCliente")
                        .HasColumnType("uniqueidentifier");

                    b.Property<decimal>("montoDescuento")
                        .HasColumnType("decimal(18,2)");

                    b.Property<decimal>("montoImpuesto")
                        .HasColumnType("decimal(18,2)");

                    b.Property<decimal>("subTotal")
                        .HasColumnType("decimal(18,2)");

                    b.Property<string>("tipoPago")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<decimal>("total")
                        .HasColumnType("decimal(18,2)");

                    b.Property<Guid?>("usuario")
                        .HasColumnType("uniqueidentifier");

                    b.HasKey("numeroFactura");

                    b.ToTable("Facturas");
                });

            modelBuilder.Entity("API_Facturacion.Models.FacturaDetalle", b =>
                {
                    b.Property<Guid>("IdDetalle")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uniqueidentifier");

                    b.Property<Guid>("ProductoidProducto")
                        .HasColumnType("uniqueidentifier");

                    b.Property<int>("cantidad")
                        .HasColumnType("int");

                    b.Property<Guid>("idProducto")
                        .HasColumnType("uniqueidentifier");

                    b.Property<int>("numeroFactura")
                        .HasColumnType("int");

                    b.Property<decimal?>("porDescuento")
                        .HasColumnType("decimal(18,2)");

                    b.Property<decimal?>("porImp")
                        .HasColumnType("decimal(18,2)");

                    b.Property<decimal?>("precioUnitario")
                        .HasColumnType("decimal(18,2)");

                    b.Property<decimal?>("subTotal")
                        .HasColumnType("decimal(18,2)");

                    b.HasKey("IdDetalle");

                    b.HasIndex("ProductoidProducto");

                    b.ToTable("FacturaDetalle");
                });

            modelBuilder.Entity("API_Facturacion.Models.Producto", b =>
                {
                    b.Property<Guid>("idProducto")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uniqueidentifier");

                    b.Property<int>("codigoBarra")
                        .HasColumnType("int");

                    b.Property<string>("description")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<int>("existencia")
                        .HasColumnType("int");

                    b.Property<decimal>("impuesto")
                        .HasColumnType("decimal(18,2)");

                    b.Property<string>("nombre")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<decimal>("precioCompra")
                        .HasColumnType("decimal(18,2)");

                    b.Property<decimal>("precioVenta")
                        .HasColumnType("decimal(18,2)");

                    b.Property<string>("tipo")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("unidadMedida")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.HasKey("idProducto");

                    b.ToTable("Productos");
                });

            modelBuilder.Entity("API_Facturacion.Models.Usuario", b =>
                {
                    b.Property<Guid>("IdUsuario")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uniqueidentifier");

                    b.Property<string>("Email")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("Nombre")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("Password")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("Role")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.HasKey("IdUsuario");

                    b.ToTable("Usuarios");
                });

            modelBuilder.Entity("API_Facturacion.Models.FacturaDetalle", b =>
                {
                    b.HasOne("API_Facturacion.Models.Producto", "Producto")
                        .WithMany()
                        .HasForeignKey("ProductoidProducto")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("Producto");
                });
#pragma warning restore 612, 618
        }
    }
}
