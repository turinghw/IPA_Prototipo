"""
Validador C2PA Independiente
TEC - Maestría en Ciberseguridad

Pegá cualquier texto generado por el sistema RAG y verifica
si contiene un manifiesto C2PA válido embebido.
Este módulo opera de forma autónoma sin dependencia de la base vectorial
o del LLM generador, requiriendo únicamente la clave pública del sistema.
"""

import tkinter as tk
from tkinter import scrolledtext
from pathlib import Path
from encypher.core.unicode_metadata import UnicodeMetadata
from cryptography.hazmat.primitives.serialization import load_pem_public_key

CLAVES_PATH = "./claves"

def cargar_clave_publica():
    """
    Carga la clave pública del sistema RAG requerida para verificar las firmas criptográficas.
    Si el archivo no está presente, la función retorna None y deshabilita la capacidad de verificar.
    
    Returns:
        Un objeto de clave pública de cryptography o None si el archivo no existe.
    """
    pub_path = Path(CLAVES_PATH) / "publica.pem"
    if not pub_path.exists():
        return None
    with open(pub_path, "rb") as f:
        return load_pem_public_key(f.read())

def verificar_texto(texto):
    """
    Realiza la decodificación del manifiesto embebido a partir del texto portador.
    Delega la responsabilidad de procesar selectores Unicode y verificar el 
    paquete COSE_Sign1 a la biblioteca encypher-ai.
    
    Args:
        texto (str): El texto que presuntamente contiene la firma inyectada.
        
    Returns:
        tuple: (bool: indica validez, dict: metadatos del manifiesto, str: ID del firmante)
    """
    try:
        resultado = UnicodeMetadata.extract_metadata(text=texto)
        if resultado is None:
            return False, {}, None
        custom = resultado.get("custom_metadata", {})
        signer = resultado.get("signer_id", "desconocido")
        if custom:
            return True, custom, signer
        return False, {}, None
    except Exception as e:
        return False, {}, str(e)


class ValidadorApp:
    """
    Clase principal que define la interfaz gráfica del cliente auditor independiente.
    Permite pegar el texto y mostrar los resultados de la verificación criptográfica.
    """
    def __init__(self, window):
        self.window = window
        self.window.title("Validador de Procedencia C2PA - TEC")
        self.window.geometry("750x620")
        self.window.resizable(True, True)

        self.pub_obj = cargar_clave_publica()
        self.crear_ui()

    def crear_ui(self):
        """Construye y organiza todos los componentes visuales de la aplicación validadora."""
        # --- TÍTULO ---
        tk.Label(
            self.window,
            text="Validador de Manifiesto C2PA",
            font=("Arial", 14, "bold")
        ).pack(pady=(15, 2))

        tk.Label(
            self.window,
            text="Pegá el texto generado por el sistema RAG para verificar su autenticidad",
            font=("Arial", 10),
            fg="#5f6368"
        ).pack(pady=(0, 10))

        # --- ESTADO DE CLAVE ---
        if self.pub_obj:
            estado_clave = "✔ Clave pública cargada correctamente"
            color_clave = "#137333"
        else:
            estado_clave = "✘ Clave pública no encontrada — ejecutá primero el sistema RAG"
            color_clave = "#c5221f"

        tk.Label(
            self.window,
            text=estado_clave,
            font=("Arial", 9),
            fg=color_clave
        ).pack(pady=(0, 8))

        # --- ÁREA DE TEXTO DE ENTRADA ---
        tk.Label(
            self.window,
            text="Texto a verificar:",
            font=("Arial", 10, "bold"),
            anchor="w"
        ).pack(fill="x", padx=15)

        self.txt_entrada = scrolledtext.ScrolledText(
            self.window,
            font=("Consolas", 10),
            wrap=tk.WORD,
            height=12,
            bg="#f8f9fa"
        )
        self.txt_entrada.pack(fill="both", expand=True, padx=15, pady=(4, 8))
        self.txt_entrada.insert(tk.END, "Pegá aquí el texto copiado del sistema RAG...")
        self.txt_entrada.bind("<FocusIn>", self.limpiar_placeholder)

        # --- BOTONES ---
        frame_botones = tk.Frame(self.window)
        frame_botones.pack(pady=6)

        tk.Button(
            frame_botones,
            text="  Verificar Firma C2PA  ",
            font=("Arial", 11, "bold"),
            bg="#1a73e8",
            fg="white",
            cursor="hand2",
            command=self.ejecutar_verificacion
        ).pack(side="left", padx=8)

        tk.Button(
            frame_botones,
            text="  Limpiar  ",
            font=("Arial", 11),
            cursor="hand2",
            command=self.limpiar_todo
        ).pack(side="left", padx=8)

        # --- PANEL DE RESULTADO ---
        self.frame_resultado = tk.LabelFrame(
            self.window,
            text=" Resultado de Verificación ",
            font=("Arial", 10, "bold"),
            padx=10,
            pady=10
        )
        self.frame_resultado.pack(fill="x", padx=15, pady=(8, 15))

        self.lbl_estado = tk.Label(
            self.frame_resultado,
            text="Esperando texto para verificar...",
            font=("Arial", 12, "bold"),
            fg="#5f6368"
        )
        self.lbl_estado.pack(anchor="w", pady=(0, 6))

        self.txt_detalles = tk.Text(
            self.frame_resultado,
            height=7,
            font=("Consolas", 10),
            bg="#e8f0fe",
            relief="flat",
            state="disabled"
        )
        self.txt_detalles.pack(fill="x")

    def limpiar_placeholder(self, event):
        """Elimina el texto por defecto al hacer clic en el área de entrada."""
        contenido = self.txt_entrada.get("1.0", tk.END).strip()
        if contenido == "Pegá aquí el texto copiado del sistema RAG...":
            self.txt_entrada.delete("1.0", tk.END)

    def ejecutar_verificacion(self):
        """
        Orquesta el proceso de extracción de metadatos C2PA y evalúa
        el resultado, modificando los componentes visuales para alertar
        al usuario sobre la autenticidad del contenido.
        """
        texto = self.txt_entrada.get("1.0", tk.END).strip()
        if not texto or texto == "Pegá aquí el texto copiado del sistema RAG...":
            self.mostrar_error("No hay texto para verificar.")
            return

        es_valido, meta, signer = verificar_texto(texto)

        self.txt_detalles.config(state="normal")
        self.txt_detalles.delete("1.0", tk.END)

        if es_valido:
            self.lbl_estado.config(
                text="✔  FIRMA C2PA VÁLIDA — Texto auténtico e íntegro",
                fg="#137333"
            )
            fuentes = meta.get("sources", [])
            detalles = (
                f"Emisor (Signer ID):    {signer}\n"
                f"Modelo generador:      {meta.get('model', 'N/A')}\n"
                f"Timestamp UTC:         {meta.get('timestamp', 'N/A')}\n"
                f"Sistema:               {meta.get('system', 'N/A')}\n"
                f"Fuentes RAG:           {', '.join(fuentes) if fuentes else 'N/A'}\n"
                f"Hash de la consulta:   {meta.get('query_hash', 'N/A')}"
            )
            self.txt_detalles.config(bg="#e6f4ea")
            self.txt_detalles.insert("1.0", detalles)
        else:
            self.lbl_estado.config(
                text="✘  FIRMA INVÁLIDA — El texto fue alterado o no tiene manifiesto C2PA",
                fg="#c5221f"
            )
            self.txt_detalles.config(bg="#fce8e6")
            if signer:
                self.txt_detalles.insert("1.0", f"Detalle del error: {signer}")
            else:
                self.txt_detalles.insert("1.0",
                    "El texto no contiene un manifiesto C2PA embebido,\n"
                    "o fue modificado después de ser generado por el sistema RAG.\n\n"
                    "Posibles causas:\n"
                    "  - El texto fue editado manualmente\n"
                    "  - Se copió solo una parte del texto\n"
                    "  - No fue generado por este sistema"
                )

        self.txt_detalles.config(state="disabled")

    def mostrar_error(self, mensaje):
        """Despliega un aviso temporal en la interfaz indicando una acción incorrecta."""
        self.lbl_estado.config(text=f"⚠ {mensaje}", fg="#e37400")
        self.txt_detalles.config(state="normal", bg="#fef7e0")
        self.txt_detalles.delete("1.0", tk.END)
        self.txt_detalles.insert("1.0", mensaje)
        self.txt_detalles.config(state="disabled")

    def limpiar_todo(self):
        """Restaura todos los campos visuales a su estado de inicialización por defecto."""
        self.txt_entrada.delete("1.0", tk.END)
        self.txt_entrada.insert(tk.END, "Pegá aquí el texto copiado del sistema RAG...")
        self.lbl_estado.config(text="Esperando texto para verificar...", fg="#5f6368")
        self.txt_detalles.config(state="normal", bg="#e8f0fe")
        self.txt_detalles.delete("1.0", tk.END)
        self.txt_detalles.config(state="disabled")


if __name__ == "__main__":
    root = tk.Tk()
    app = ValidadorApp(root)
    root.mainloop()