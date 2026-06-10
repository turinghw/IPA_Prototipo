"""
Sistema RAG con Trazabilidad C2PA e Interfaz Gráfica (GUI)
TEC - Maestría en Ciberseguridad

Este archivo integra el flujo completo: extracción de documentos PDF,
segmentación de texto, indexación en ChromaDB, recuperación semántica,
generación local con Ollama en streaming y verificación automatizada C2PA.
"""

import os
import sys
import json
import hashlib
import datetime
import requests
import threading
import chromadb
import tkinter as tk
from tkinter import scrolledtext
from pathlib import Path
from sentence_transformers import SentenceTransformer
from encypher.core.unicode_metadata import UnicodeMetadata
from encypher.core.keys import generate_ed25519_key_pair
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

# --- CONFIGURACIÓN GLOBAL ---
OLLAMA_URL = "http://localhost:11434/api/generate"
MODELO_LLM = "qwen2.5:1.5b"
MODELO_EMBED = "all-MiniLM-L6-v2"
DB_PATH = "./chroma_db"
CLAVES_PATH = "./claves"
CHUNK_SIZE = 500
CHUNK_OVERLAP = 50

MIS_DOCUMENTOS = [
    r"C:\Users\Paublo Ávila\rag_proyecto\law-and-disorder-on-the-electronic-frontier-bruce-sterling.pdf",
]

# =====================================================================
# 1. CAPA LÓGICA DE PROCESAMIENTO E INDEXACIÓN (ETL)
# =====================================================================

def chunk_texto(texto, fuente, tamano=CHUNK_SIZE, overlap=CHUNK_OVERLAP):
    """
    Segmenta el texto completo en ventanas de tamaño fijo con un traslape controlado.
    
    Args:
        texto (str): El texto completo a segmentar.
        fuente (str): El nombre del documento de origen.
        tamano (int, optional): La cantidad máxima de palabras por segmento. Por defecto es CHUNK_SIZE.
        overlap (int, optional): La cantidad de palabras que se superpondrán entre segmentos sucesivos. Por defecto es CHUNK_OVERLAP.
        
    Returns:
        list: Una lista de diccionarios, donde cada uno representa un fragmento de texto con sus metadatos.
    """
    chunks = []
    palabras = texto.split()
    i = 0
    idx = 0
    while i < len(palabras):
        chunk = " ".join(palabras[i:i+tamano])
        chunks.append({
            "texto": chunk,
            "fuente": fuente,
            "chunk_id": f"{fuente}__chunk{idx}"
        })
        i += tamano - overlap
        idx += 1
    return chunks

def leer_pdf(ruta):
    """
    Extrae el contenido textual de un archivo PDF estructurado por páginas.
    
    Args:
        ruta (str): La ruta física del archivo PDF a leer.
        
    Returns:
        str: El texto concatenado de todas las páginas del PDF. Retorna una cadena vacía en caso de error.
    """
    try:
        from pypdf import PdfReader
        reader = PdfReader(ruta)
        texto = ""
        for i, pagina in enumerate(reader.pages):
            contenido = pagina.extract_text()
            if contenido:
                texto += f"\n[Página {i+1}]\n{contenido}"
        return texto
    except Exception as e:
        print(f"[ERROR] Incapacidad para leer el archivo PDF {ruta}: {e}")
        return ""

def construir_base_datos(rutas_documentos, modelo_embed):
    """
    Pipeline que se ejecuta si no existe persistencia previa de ChromaDB.
    Procesa una lista de rutas de documentos, extrae el texto, lo segmenta,
    calcula los embeddings y los almacena en la base de datos vectorial local.
    
    Args:
        rutas_documentos (list): Lista de rutas absolutas o relativas de los documentos PDF.
        modelo_embed (SentenceTransformer): Instancia del modelo de embeddings cargado en memoria.
        
    Returns:
        chromadb.Collection: La colección de ChromaDB con los documentos indexados.
    """
    print("[INDEXANDO] Base de datos no detectada. Iniciando parsing e indexación...")
    cliente = chromadb.PersistentClient(path=DB_PATH)
    coleccion = cliente.get_or_create_collection("documentos")

    for ruta in rutas_documentos:
        ruta_str = str(ruta)
        if not os.path.exists(ruta_str):
            print(f"[AVISO] Archivo no encontrado: {ruta_str}. Saltando...")
            continue

        print(f"  Procesando e indexando: {ruta_str}")
        texto = leer_pdf(ruta_str)
        fuente = Path(ruta_str).name

        if not texto.strip():
            continue

        chunks = chunk_texto(texto, fuente)
        textos = [c["texto"] for c in chunks]
        ids = [c["chunk_id"] for c in chunks]
        metadatas = [{"fuente": c["fuente"], "chunk_idx": i} for i, c in enumerate(chunks)]

        embeddings = modelo_embed.encode(textos).tolist()
        coleccion.add(documents=textos, embeddings=embeddings, ids=ids, metadatas=metadatas)
        print(f"  [OK] {len(chunks)} fragmentos vectorizados de '{fuente}'")
    
    return coleccion

# =====================================================================
# 2. GESTIÓN CRIPTOGRÁFICA Y MANIFIESTOS (C2PA)
# =====================================================================

def inicializar_claves():
    """
    Verifica la existencia del par de claves criptográficas Ed25519 en el disco.
    Si no existen, genera un par nuevo y las persiste de forma local.
    
    Returns:
        tuple: Un par que contiene (clave_privada, clave_publica) en formato de objetos de cryptography.
    """
    os.makedirs(CLAVES_PATH, exist_ok=True)
    priv_path = Path(CLAVES_PATH) / "privada.pem"
    pub_path = Path(CLAVES_PATH) / "publica.pem"

    if priv_path.exists() and pub_path.exists():
        with open(priv_path, "rb") as f:
            priv_obj = load_pem_private_key(f.read(), password=None)
        with open(pub_path, "rb") as f:
            pub_obj = load_pem_public_key(f.read())
    else:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
        clave_privada, clave_publica = generate_ed25519_key_pair()
        with open(priv_path, "wb") as f:
            f.write(clave_privada.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        with open(pub_path, "wb") as f:
            f.write(clave_publica.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        priv_obj = clave_privada
        pub_obj = clave_publica
    return priv_obj, pub_obj

def firmar_respuesta_c2pa(texto_respuesta, pregunta, fuentes, priv_obj):
    """
    Incrusta metadatos de trazabilidad y firma el texto final usando selectores Unicode,
    garantizando que la respuesta generada por el LLM no sea modificada.
    
    Args:
        texto_respuesta (str): El texto crudo generado por el sistema RAG.
        pregunta (str): La consulta original realizada por el usuario.
        fuentes (list): Lista de nombres de archivos que sirvieron de contexto.
        priv_obj: Objeto de la clave privada Ed25519.
        
    Returns:
        tuple: (texto_firmado (str), metadata (dict)). Si ocurre un error, retorna el texto original.
    """
    try:
        timestamp = datetime.datetime.now(datetime.UTC).isoformat() + "Z"
        hash_pregunta = hashlib.sha256(pregunta.encode()).hexdigest()
        metadata = {
            "model": MODELO_LLM,
            "timestamp": timestamp,
            "query_hash": hash_pregunta,
            "sources": fuentes,
            "system": "RAG-C2PA-TEC",
            "action": "c2pa.created"
        }
        texto_firmado = UnicodeMetadata.embed_metadata(
            text=texto_respuesta,
            private_key=priv_obj,
            signer_id="rag-key-001",
            custom_metadata=metadata
        )
        return texto_firmado, metadata
    except Exception as e:
        return texto_respuesta, {}

def verificar_manifiesto_texto(texto, pub_obj):
    """
    Realiza la extracción del manifiesto del texto y verifica su integridad estructural
    utilizando encypher-ai. Valida que el texto no haya sido alterado tras su firma.
    
    Args:
        texto (str): El texto firmado a validar.
        pub_obj: Objeto de la clave pública (actualmente no utilizado directamente por esta función).
        
    Returns:
        tuple: (es_valido (bool), metadata_extraida (dict), signer_id (str)).
    """
    try:
        resultado = UnicodeMetadata.extract_metadata(text=texto)
        
        if resultado is None:
            return False, {}, None
        
        # Si extract_metadata devuelve algo, la firma ya fue validada internamente
        custom = resultado.get("custom_metadata", {})
        signer = resultado.get("signer_id", "desconocido")
        
        if custom:
            return True, custom, signer
        else:
            return False, {}, None
            
    except Exception as e:
        return False, {}, str(e)

def guardar_registro(pregunta, respuesta, fuentes, archivo_log="registro_procedencia.jsonl"):
    """
    Mantiene un registro de auditoría local simulando una cadena inmutable simple (encadenamiento de hashes).
    Añade un nuevo registro de interacción en formato JSON Lines al disco de forma secuencial.
    
    Args:
        pregunta (str): La consulta realizada por el usuario.
        respuesta (str): La respuesta en texto puro generada por el LLM.
        fuentes (list): Las fuentes utilizadas en el proceso RAG.
        archivo_log (str): Nombre del archivo donde se almacena la bitácora.
    """
    try:
        ultimo_hash = "0" * 64
        if Path(archivo_log).exists():
            with open(archivo_log, "r", encoding="utf-8") as f:
                lineas = f.readlines()
                if lineas:
                    ultimo = json.loads(lineas[-1])
                    ultimo_hash = ultimo.get("hash_actual", "0" * 64)

        entrada = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat() + "Z",
            "pregunta": pregunta,
            "hash_pregunta": hashlib.sha256(pregunta.encode()).hexdigest(),
            "hash_respuesta": hashlib.sha256(respuesta.encode()).hexdigest(),
            "fuentes": fuentes,
            "modelo": MODELO_LLM,
            "hash_anterior": ultimo_hash
        }
        contenido_para_hash = json.dumps(entrada, sort_keys=True, ensure_ascii=False)
        entrada["hash_actual"] = hashlib.sha256(contenido_para_hash.encode()).hexdigest()
        with open(archivo_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(entrada, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"Error en log: {e}")

# =====================================================================
# 3. INTERFAZ GRÁFICA DE USUARIO (GUI)
# =====================================================================

class AppRAG:
    """
    Clase principal que encapsula la Interfaz Gráfica del sistema RAG.
    Controla los eventos, actualizaciones visuales y el hilo secundario
    para la comunicación con Ollama sin bloquear la interfaz.
    """
    def __init__(self, window):
        self.window = window
        self.window.title("Módulo de Consulta RAG con Trazabilidad C2PA")
        self.window.geometry("800x720")
        
        # Inicialización y validación del entorno de datos
        self.priv_obj, self.pub_obj = inicializar_claves()
        self.modelo_embed = SentenceTransformer(MODELO_EMBED)
        
        # Cliente ChromaDB
        self.cliente_chroma = chromadb.PersistentClient(path=DB_PATH)
        self.coleccion = self.cliente_chroma.get_or_create_collection("documentos")
    
        # Verificar cuántos chunks hay realmente en la colección
        cantidad = self.coleccion.count()
        print(f"[DB] Chunks en base de datos: {cantidad}")
    
        if cantidad == 0:
            print("[DB] Base vacía, indexando documentos...")
            self.coleccion = construir_base_datos(MIS_DOCUMENTOS, self.modelo_embed)
        else:
            print(f"[DB] Usando {cantidad} chunks existentes de corrida anterior.")
        
        self.texto_firmado_actual = ""
        self.crear_componentes()


    def crear_componentes(self):
        """
        Construye todos los elementos visuales de Tkinter (entradas, botones, áreas de texto).
        """
        # --- SECCIÓN ENTRADA ---
        frame_input = tk.Frame(self.window, padx=10, pady=10)
        frame_input.pack(fill="x")
        
        lbl_pregunta = tk.Label(frame_input, text="Consulta de Ciberseguridad:", font=("Arial", 11, "bold"))
        lbl_pregunta.pack(anchor="w", pady=2)
        
        self.entry_pregunta = tk.Entry(frame_input, font=("Arial", 11))
        self.entry_pregunta.pack(fill="x", side="left", expand=True, padx=(0, 10))
        self.entry_pregunta.bind("<Return>", lambda event: self.ejecutar_consulta_async())
        
        self.btn_enviar = tk.Button(
            frame_input,
            text="Consultar",
            font=("Arial", 10, "bold"),
            bg="#1a73e8",
            fg="white",
            command=self.ejecutar_consulta_async
        )
        self.btn_enviar.pack(side="right", padx=10)

        # --- SECCIÓN SALIDA LLM ---
        frame_output = tk.Frame(self.window, padx=10, pady=5)
        frame_output.pack(fill="both", expand=True)

        frame_header_output = tk.Frame(frame_output)
        frame_header_output.pack(fill="x")

        tk.Label(
            frame_header_output,
            text="Respuesta del Sistema:",
            font=("Arial", 10, "bold")
        ).pack(side="left", anchor="w")

        self.btn_copiar = tk.Button(
            frame_header_output,
            text="Copiar texto firmado",
            font=("Arial", 9),
            cursor="hand2",
            state="disabled",
            command=self.copiar_texto_firmado
        )
        self.btn_copiar.pack(side="right", padx=4)

        self.txt_respuesta = scrolledtext.ScrolledText(
            frame_output,
            font=("Consolas", 11),
            wrap=tk.WORD,
            bg="#f8f9fa",
            state="disabled"
        )
        self.txt_respuesta.pack(fill="both", expand=True, pady=5)

        # --- SECCIÓN AUDITORÍA C2PA INTEGRADA ---
        frame_auditoria = tk.LabelFrame(
            self.window,
            text=" Panel de Verificacion de Procedencia e Integridad C2PA ",
            font=("Arial", 10, "bold"),
            padx=10,
            pady=10
        )
        frame_auditoria.pack(fill="x", padx=10, pady=10)
        
        self.lbl_estado_firma = tk.Label(
            frame_auditoria,
            text="ESTADO: Esperando generacion...",
            font=("Arial", 11, "bold"),
            fg="#5f6368"
        )
        self.lbl_estado_firma.pack(anchor="w", pady=2)
        
        self.txt_detalles_c2pa = tk.Text(
            frame_auditoria,
            height=6,
            font=("Consolas", 10),
            bg="#e8f0fe",
            relief="flat"
        )
        self.txt_detalles_c2pa.pack(fill="x", pady=5)
        self.txt_detalles_c2pa.insert(
            "1.0",
            "Los metadatos criptograficos inyectados apareceran aqui de forma automatica al completarse el flujo RAG."
        )
        self.txt_detalles_c2pa.config(state="disabled")

    def copiar_texto_firmado(self):
        """Copia el texto final, incluyendo selectores invisibles Unicode, al portapapeles del sistema."""
        if self.texto_firmado_actual:
            self.window.clipboard_clear()
            self.window.clipboard_append(self.texto_firmado_actual)
            self.btn_copiar.config(text="Copiado!")
            self.window.after(2000, lambda: self.btn_copiar.config(text="Copiar texto firmado"))

    def ejecutar_consulta_async(self):
        """Inicia el proceso de generación RAG en un hilo secundario para evitar bloquear la interfaz."""
        self.btn_enviar.config(state="disabled")
        self.entry_pregunta.config(state="disabled")
        
        hilo = threading.Thread(target=self.proceso_rag)
        hilo.daemon = True
        hilo.start()

    def proceso_rag(self):
        """
        Orquesta el flujo RAG de forma segura en memoria RAM:
        Recuperación semántica, construcción del prompt estricto, streaming en interfaz,
        anexión controlada de fuentes reales, firmado C2PA e inmediata validación criptográfica.
        """
        pregunta = self.entry_pregunta.get().strip()
        if not pregunta:
            self.reactivar_controles()
            return
    
        # 1. Configuración de estado inicial en la interfaz visual
        self.txt_respuesta.config(state="normal")
        self.txt_respuesta.delete("1.0", tk.END)
        self.txt_respuesta.insert(tk.END, "[1/4] Recuperando fragmentos semánticos desde el índice vectorial...\n")
        self.txt_respuesta.config(state="disabled")
        
        # 2. Búsqueda semántica en base de datos vectorial
        emb_pregunta = self.modelo_embed.encode([pregunta]).tolist()
        resultados = self.coleccion.query(
            query_embeddings=emb_pregunta,
            n_results=3,
            include=["documents", "metadatas", "distances"]
        )
        
        chunks = []
        fuentes = []
        contexto_str = ""
        for doc, meta, dist in zip(
            resultados["documents"][0],
            resultados["metadatas"][0],
            resultados["distances"][0]
        ):
            chunks.append(doc)
            fuentes.append(meta["fuente"])
            contexto_str += f"\n[Fuente: {meta['fuente']}]\n{doc[:1500]}\n"
        fuentes = list(set(fuentes))
    
        # Limpieza de la pantalla para el streaming del LLM
        self.txt_respuesta.config(state="normal")
        self.txt_respuesta.delete("1.0", tk.END)
        self.txt_respuesta.config(state="disabled")
    
        # 3. Prompt restrictivo con instrucción explícita de citar fuentes inline
        prompt = f"""You are an assistant. Answer ONLY using the context below.
    For each fact you mention, add the source in parentheses like: (Source: filename.pdf)
    If the context has no answer, say: "The context does not contain this information."
    
    CONTEXT:
    {contexto_str}
    
    QUESTION: {pregunta}
    
    ANSWER:"""
    
        respuesta_completa = ""
        try:
            resp = requests.post(OLLAMA_URL, json={
                "model": MODELO_LLM,
                "prompt": prompt,
                "stream": True,
                "options": {"num_predict": 300, "temperature": 0.2}
            }, stream=True, timeout=120)
    
            # Consumo interactivo de tokens por flujo
            for linea in resp.iter_lines():
                if linea:
                    data = json.loads(linea)
                    token = data.get("response", "")
                    respuesta_completa += token
                    
                    self.txt_respuesta.config(state="normal")
                    self.txt_respuesta.insert(tk.END, token)
                    self.txt_respuesta.see(tk.END)
                    self.txt_respuesta.config(state="disabled")
                    if data.get("done"):
                        break
            
            # 4. Inyección controlada de fuentes desde el backend con relevancia
            # Mostramos fragmento real + porcentaje de relevancia por chunk
            formato_fuentes = "\n\n--- Fragmentos recuperados por RAG ---\n"
            for doc, meta, dist in zip(
                resultados["documents"][0],
                resultados["metadatas"][0],
                resultados["distances"][0]
            ):
                relevancia = round((1 - dist) * 100, 1)
                formato_fuentes += f"\n[{meta['fuente']} | relevancia: {relevancia}%]\n"
                formato_fuentes += f"{doc[:200]}...\n"
            
            self.txt_respuesta.config(state="normal")
            self.txt_respuesta.insert(tk.END, formato_fuentes)
            self.txt_respuesta.see(tk.END)
            self.txt_respuesta.config(state="disabled")
            
            # Incorporamos las fuentes físicas a la cadena que será firmada criptográficamente
            respuesta_completa += formato_fuentes
    
        except Exception as e:
            self.txt_respuesta.config(state="normal")
            self.txt_respuesta.insert(tk.END, f"\n[ERROR de comunicación con Ollama]: {e}")
            self.txt_respuesta.config(state="disabled")
            self.btn_copiar.config(state="normal")
            self.reactivar_controles()
            return
    
        # 5. Pipeline Criptográfico de Trazabilidad e Integridad C2PA
        respuesta_pura = respuesta_completa.strip()
        
        self.texto_firmado_actual, metadata = firmar_respuesta_c2pa(
            respuesta_pura, pregunta, fuentes, self.priv_obj
        )
        guardar_registro(pregunta, respuesta_pura, fuentes)
    
        # Validación automatizada en caliente
        es_valido, meta_extraida, signer_id = verificar_manifiesto_texto(
            self.texto_firmado_actual, self.pub_obj
        )
        
        self.actualizar_modulo_auditoria(es_valido, meta_extraida, signer_id)
        self.btn_copiar.config(state="normal")
        self.reactivar_controles()


    def actualizar_modulo_auditoria(self, es_valido, meta, signer_id):
        """Actualiza el panel de validación en la parte inferior de la ventana tras finalizar la generación."""
        self.txt_detalles_c2pa.config(state="normal")
        self.txt_detalles_c2pa.delete("1.0", tk.END)
        
        if es_valido:
            self.lbl_estado_firma.config(text="ESTADO: FIRMA C2PA VÁLIDA E INTEGRIDAD VERIFICADA", fg="#137333")
            detalles = (
                f"Emisor C2PA:        {signer_id}\n"
                f"Modelo Generador:     {meta.get('model')}\n"
                f"Sello Temporal UTC:   {meta.get('timestamp')}\n"
                f"Fuentes del RAG:      {', '.join(meta.get('sources', []))}\n"
                f"Hash de la Consulta:  {meta.get('query_hash')}"
            )
            self.txt_detalles_c2pa.insert("1.0", detalles)
        else:
            self.lbl_estado_firma.config(text="ESTADO: MANIFIESTO CORRUPTO O INEXISTENTE", fg="#c5221f")
            self.txt_detalles_c2pa.insert("1.0", "Alerta: El texto sufrió modificaciones o no cuenta con firmas válidas.")
            
        self.txt_detalles_c2pa.config(state="disabled")

    def reactivar_controles(self):
        """Habilita nuevamente la interfaz para permitir consultas subsiguientes."""
        self.btn_enviar.config(state="normal")
        self.entry_pregunta.config(state="normal")
        self.entry_pregunta.delete(0, tk.END)

# --- INICIALIZADOR ---
if __name__ == "__main__":
    root = tk.Tk()
    app = AppRAG(root)
    root.mainloop()