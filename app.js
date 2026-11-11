
"use strict";

/* =================================
   LC HTML SECURITY SCANNER
   Motor de análisis estático local
================================= */

const htmlInput = document.getElementById("htmlInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const clearBtn = document.getElementById("clearBtn");
const fileInput = document.getElementById("fileInput");
const fileName = document.getElementById("fileName");
const exportBtn = document.getElementById("exportBtn");

const resultSection = document.getElementById("resultSection");
const riskTitle = document.getElementById("riskTitle");
const riskDescription = document.getElementById("riskDescription");
const riskBadge = document.getElementById("riskBadge");
const riskScore = document.getElementById("riskScore");
const scoreBar = document.getElementById("scoreBar");

const criticalCount = document.getElementById("criticalCount");
const highCount = document.getElementById("highCount");
const mediumCount = document.getElementById("mediumCount");
const lowCount = document.getElementById("lowCount");

const findingsList = document.getElementById("findingsList");

let lastAnalysis = null;
let analyzedFileName = "Código pegado";


/* =================================
   REGLAS DE DETECCIÓN
================================= */

const RULES = [
  {
    id: "eval",
    title: "Uso de eval()",
    level: "critical",
    points: 30,
    pattern: /\beval\s*\(/gi,
    description: "Puede ejecutar código JavaScript construido dinámicamente."
  },
  {
    id: "function",
    title: "Constructor Function()",
    level: "critical",
    points: 30,
    pattern: /\bnew\s+Function\s*\(/gi,
    description: "Permite crear y ejecutar código dinámicamente."
  },
  {
    id: "javascript-url",
    title: "URL javascript:",
    level: "critical",
    points: 30,
    pattern: /\bjavascript\s*:/gi,
    description: "Puede ejecutar JavaScript desde una URL o atributo HTML."
  },
  {
    id: "iframe",
    title: "Iframe externo",
    level: "medium",
    points: 10,
    pattern: /<iframe\b[^>]*\bsrc\s*=\s*["'][^"']+/gi,
    description: "Carga contenido dentro de un marco. Revisa su procedencia."
  },
  {
    id: "external-script",
    title: "Script externo",
    level: "medium",
    points: 12,
    pattern: /<script\b[^>]*\bsrc\s*=\s*["']https?:\/\//gi,
    description: "Carga JavaScript desde un servidor externo."
  },
  {
    id: "fetch",
    title: "Solicitud fetch()",
    level: "medium",
    points: 8,
    pattern: /\bfetch\s*\(/gi,
    description: "Puede transmitir o recibir información mediante HTTP."
  },
  {
    id: "xhr",
    title: "XMLHttpRequest",
    level: "medium",
    points: 8,
    pattern: /\bXMLHttpRequest\b/gi,
    description: "Permite realizar solicitudes HTTP."
  },
  {
    id: "websocket",
    title: "WebSocket",
    level: "medium",
    points: 8,
    pattern: /\bnew\s+WebSocket\s*\(/gi,
    description: "Puede establecer conexiones de comunicación persistentes."
  },
  {
    id: "storage",
    title: "Acceso a almacenamiento",
    level: "low",
    points: 3,
    pattern: /\b(localStorage|sessionStorage)\b/gi,
    description: "Accede al almacenamiento del navegador."
  },
  {
    id: "cookies",
    title: "Acceso a cookies",
    level: "high",
    points: 15,
    pattern: /\bdocument\.cookie\b/gi,
    description: "Accede a cookies. Revisa si intenta extraer información sensible."
  },
  {
    id: "location",
    title: "Manipulación de ubicación",
    level: "high",
    points: 12,
    pattern: /\b(window\.location|location\.href|location\.replace|location\.assign)\b/gi,
    description: "Puede modificar la dirección o redirigir al usuario."
  },
  {
    id: "window-open",
    title: "Apertura de ventanas",
    level: "medium",
    points: 7,
    pattern: /\bwindow\.open\s*\(/gi,
    description: "Puede abrir ventanas o pestañas."
  },
  {
    id: "innerhtml",
    title: "Uso de innerHTML",
    level: "medium",
    points: 7,
    pattern: /\binnerHTML\b/gi,
    description: "Puede insertar HTML dinámicamente. Revisa el origen del contenido."
  },
  {
    id: "document-write",
    title: "document.write()",
    level: "medium",
    points: 8,
    pattern: /\bdocument\.write\s*\(/gi,
    description: "Modifica directamente el documento HTML."
  },
  {
    id: "dynamic-timer",
    title: "Código dinámico en temporizador",
    level: "high",
    points: 15,
    pattern: /\b(setTimeout|setInterval)\s*\(\s*["'`]/gi,
    description: "Se encontró código pasado como texto a un temporizador."
  },
  {
    id: "event-handler",
    title: "Event handler inline",
    level: "low",
    points: 3,
    pattern: /\bon(load|error|click|mouseover|focus|submit|change)\s*=/gi,
    description: "Se encontró un manejador de eventos directamente en HTML."
  },
  {
    id: "form-external",
    title: "Formulario externo",
    level: "high",
    points: 15,
    pattern: /<form\b[^>]*\baction\s*=\s*["']https?:\/\//gi,
    description: "El formulario envía información a una dirección externa."
  },
  {
    id: "meta-refresh",
    title: "Redirección automática",
    level: "high",
    points: 15,
    pattern: /<meta\b[^>]*http-equiv\s*=\s*["']refresh["']/gi,
    description: "Se detectó una posible redirección automática."
  },
  {
    id: "base64",
    title: "Conversión Base64",
    level: "medium",
    points: 10,
    pattern: /\b(atob|btoa)\s*\(/gi,
    description: "Puede utilizarse para codificar o decodificar datos."
  },
  {
    id: "obfuscation",
    title: "Posible ofuscación",
    level: "high",
    points: 15,
    pattern: /\b(String\.fromCharCode|unescape|decodeURIComponent)\s*\(/gi,
    description: "Se encontró una función que puede utilizarse en técnicas de ofuscación."
  }
];


/* =================================
   UTILIDADES
================================= */

function escapeHTML(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function getLineNumber(text, index) {
  return text.substring(0, index).split("\n").length;
}

function getLine(text, index) {
  return text.split("\n")[getLineNumber(text, index) - 1] || "";
}


/* =================================
   MOTOR DE ANÁLISIS
================================= */

function analyzeHTML(html) {
  const findings = [];
  let score = 0;

  for (const rule of RULES) {
    const regex = new RegExp(
      rule.pattern.source,
      rule.pattern.flags
    );

    let match;
    let occurrences = 0;

    while ((match = regex.exec(html)) !== null) {
      findings.push({
        id: rule.id,
        title: rule.title,
        level: rule.level,
        points: rule.points,
        description: rule.description,
        line: getLineNumber(html, match.index),
        code: getLine(html, match.index).trim()
      });

      score += rule.points;
      occurrences++;

      if (occurrences >= 3) break;
    }
  }

  // Detectar JavaScript inline

  const inlineRegex =
    /<script\b(?![^>]*\bsrc\s*=)[^>]*>/gi;

  let inlineMatch;

  while ((inlineMatch = inlineRegex.exec(html)) !== null) {
    findings.push({
      id: "inline-script",
      title: "JavaScript inline",
      level: "low",
      points: 3,
      description: "El documento contiene JavaScript directamente dentro del HTML.",
      line: getLineNumber(html, inlineMatch.index),
      code: getLine(html, inlineMatch.index).trim()
    });

    score += 3;

    if (findings.filter(f => f.id === "inline-script").length >= 3) break;
  }

  // Detectar URLs externas

  const urls = html.match(/https?:\/\/[^\s"'<>]+/gi) || [];
  const uniqueURLs = [...new Set(urls)];

  if (uniqueURLs.length) {
    const points = Math.min(uniqueURLs.length * 2, 10);

    findings.push({
      id: "external-url",
      title: "Recursos externos detectados",
      level: "medium",
      points,
      description: `Se detectaron ${uniqueURLs.length} URL(s) externas.`,
      line: 1,
      code: uniqueURLs.slice(0, 3).join(" | ")
    });

    score += points;
  }

  return {
    score: Math.min(score, 100),
    findings,
    analyzedAt: new Date().toISOString()
  };
}


/* =================================
   CLASIFICACIÓN DE RIESGO
================================= */

function getRisk(score, findings = []) {

  if (findings.some(f => f.level === "critical")) {
    return {
      title: "Riesgo crítico",
      description: "Se detectó código con capacidad de ejecución dinámica o comportamiento potencialmente peligroso.",
      label: "CRÍTICO",
      className: "level-critical"
    };
  }

  if (findings.some(f => f.level === "high")) {
    return {
      title: "Riesgo alto",
      description: "Se encontraron indicadores que requieren revisión.",
      label: "ALTO",
      className: "level-high"
    };
  }

  if (score === 0) {
    return {
      title: "Sin patrones detectados",
      description: "No se encontraron coincidencias con las reglas actuales. Esto no garantiza que el HTML sea seguro.",
      label: "SIN HALLAZGOS",
      className: "level-low"
    };
  }

  if (score <= 20) {
    return {
      title: "Riesgo bajo",
      description: "Se encontraron elementos que conviene revisar.",
      label: "BAJO",
      className: "level-low"
    };
  }

  if (score <= 45) {
    return {
      title: "Riesgo medio",
      description: "Hay patrones que requieren revisión.",
      label: "MEDIO",
      className: "level-medium"
    };
  }

  if (score <= 70) {
    return {
      title: "Riesgo alto",
      description: "Se encontraron varios indicadores sospechosos.",
      label: "ALTO",
      className: "level-high"
    };
  }

  return {
    title: "Riesgo crítico",
    description: "Se encontraron múltiples indicadores peligrosos.",
    label: "CRÍTICO",
    className: "level-critical"
  };
}


/* =================================
   NIVELES
================================= */

function getLevelLabel(level) {
  const labels = {
    low: "BAJO",
    medium: "MEDIO",
    high: "ALTO",
    critical: "CRÍTICO"
  };

  return labels[level] || level.toUpperCase();
}

function getLevelClass(level) {
  return {
    low: "level-low",
    medium: "level-medium",
    high: "level-high",
    critical: "level-critical"
  }[level] || "level-low";
}


/* =================================
   MOSTRAR RESULTADOS
================================= */

function showResults(result) {
  const risk = getRisk(result.score, result.findings);

  resultSection.classList.remove("hidden");

  riskTitle.textContent = risk.title;
  riskDescription.textContent = risk.description;
  riskBadge.textContent = risk.label;
  riskBadge.className = "risk-badge " + risk.className;

  riskScore.textContent = `${result.score}/100`;
  scoreBar.style.width = `${result.score}%`;

  const barColor = {
    "level-low": "var(--safe)",
    "level-medium": "var(--medium)",
    "level-high": "var(--high)",
    "level-critical": "var(--critical)"
  };

  scoreBar.style.background = barColor[risk.className];

  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };

  result.findings.forEach(f => counts[f.level]++);

  criticalCount.textContent = counts.critical;
  highCount.textContent = counts.high;
  mediumCount.textContent = counts.medium;
  lowCount.textContent = counts.low;

  findingsList.innerHTML = "";

  if (!result.findings.length) {
    const item = document.createElement("div");
    item.className = "finding";
    item.textContent = "No se encontraron patrones coincidentes con las reglas actuales.";
    findingsList.appendChild(item);
    return;
  }

  result.findings.forEach(finding => {
    const item = document.createElement("div");
    item.className = "finding";

    item.innerHTML = `
      <div class="finding-top">
        <div class="finding-title">${escapeHTML(finding.title)}</div>
        <div class="finding-level ${getLevelClass(finding.level)}">
          ${getLevelLabel(finding.level)}
        </div>
      </div>

      <div class="finding-description">
        ${escapeHTML(finding.description)}
      </div>

      <div class="finding-description">
        Línea ${finding.line}
      </div>

      <code class="finding-code">${escapeHTML(finding.code)}</code>
    `;

    findingsList.appendChild(item);
  });
}


/* =================================
   CARGAR ARCHIVOS HTML
================================= */

fileInput.addEventListener("change", async () => {
  const file = fileInput.files[0];

  if (!file) return;

  if (!/\.(html|htm)$/i.test(file.name)) {
    alert("Selecciona un archivo HTML válido.");
    fileInput.value = "";
    return;
  }

  if (file.size > 5 * 1024 * 1024) {
    alert("El archivo supera el límite de 5 MB.");
    fileInput.value = "";
    return;
  }

  try {
    const content = await file.text();

    htmlInput.value = content;
    analyzedFileName = file.name;
    fileName.textContent = "📄 " + file.name;

    lastAnalysis = null;
    resultSection.classList.add("hidden");

    alert("Archivo cargado correctamente. Ya puedes analizarlo.");

  } catch (error) {
    alert("No fue posible leer el archivo.");
  }
});


/* =================================
   BOTÓN ANALIZAR
================================= */

analyzeBtn.addEventListener("click", () => {
  const html = htmlInput.value;

  if (!html.trim()) {
    alert("Pega o carga primero un archivo HTML.");
    htmlInput.focus();
    return;
  }

  lastAnalysis = analyzeHTML(html);

  if (!fileInput.files.length) {
    analyzedFileName = "Código pegado";
  }

  showResults(lastAnalysis);

  resultSection.scrollIntoView({
    behavior: "smooth",
    block: "start"
  });
});


/* =================================
   LIMPIAR
================================= */

clearBtn.addEventListener("click", () => {
  htmlInput.value = "";
  fileInput.value = "";

  fileName.textContent = "Ningún archivo seleccionado";
  analyzedFileName = "Código pegado";

  lastAnalysis = null;

  resultSection.classList.add("hidden");
  findingsList.innerHTML = "";

  riskScore.textContent = "0/100";
  scoreBar.style.width = "0%";

  htmlInput.focus();
});


/* =================================
   EXPORTAR INFORME
================================= */

exportBtn.addEventListener("click", () => {
  if (!lastAnalysis) {
    alert("Primero debes analizar un HTML.");
    return;
  }

  const result = lastAnalysis;
  const risk = getRisk(result.score, result.findings);

  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };

  result.findings.forEach(f => counts[f.level]++);

  const date = new Date(result.analyzedAt).toLocaleString("es-MX");

  const findings = result.findings.map(f => `
    <article class="finding">
      <h3>${escapeHTML(f.title)}</h3>
      <p><strong>Nivel:</strong> ${getLevelLabel(f.level)}</p>
      <p>${escapeHTML(f.description)}</p>
      <p><strong>Línea:</strong> ${f.line}</p>
      <pre>${escapeHTML(f.code)}</pre>
    </article>
  `).join("");

  const report = `
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Informe LC Security Scanner</title>

<style>
body {
  font-family: Arial, sans-serif;
  color: #172033;
  padding: 25px;
  line-height: 1.5;
}
h1 { color: #b8860b; }
.header {
  border-bottom: 3px solid #d6ad36;
  padding-bottom: 15px;
}
.score {
  font-size: 25px;
  font-weight: bold;
}
.finding {
  border: 1px solid #ccc;
  border-radius: 8px;
  padding: 12px;
  margin: 12px 0;
  break-inside: avoid;
}
pre {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  background: #f1f1f1;
  padding: 10px;
  font-size: 11px;
}
.footer {
  margin-top: 30px;
  border-top: 1px solid #ccc;
  padding-top: 10px;
  font-size: 11px;
}
button {
  padding: 12px 20px;
  border: 0;
  border-radius: 8px;
  background: #d6ad36;
  font-weight: bold;
}
@media print {
  button { display: none; }
  body { padding: 0; }
}
</style>
</head>

<body>

<div class="header">
<h1>LC HTML Security Scanner</h1>
<p>Informe de análisis de seguridad HTML</p>
</div>

<p><strong>Archivo:</strong> ${escapeHTML(analyzedFileName)}</p>
<p><strong>Fecha:</strong> ${escapeHTML(date)}</p>

<div class="score">
Riesgo: ${risk.label} — ${result.score}/100
</div>

<p>${escapeHTML(risk.description)}</p>

<h2>Resumen de hallazgos</h2>
<ul>
<li>Críticos: ${counts.critical}</li>
<li>Altos: ${counts.high}</li>
<li>Medios: ${counts.medium}</li>
<li>Bajos: ${counts.low}</li>
</ul>

<h2>Detalle de detecciones</h2>

${findings || "<p>Sin patrones detectados.</p>"}

<div class="footer">
LC HTML Security Scanner · Análisis estático local.
Este informe no constituye una certificación de seguridad.
</div>

<button onclick="window.print()">Imprimir o guardar como PDF</button>

</body>
</html>`;

  const blob = new Blob(
    [report],
    { type: "text/html;charset=utf-8" }
  );

  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = "LC-Security-Report.html";

  document.body.appendChild(link);
  link.click();
  link.remove();

  setTimeout(() => URL.revokeObjectURL(url), 60000);
});


/* =================================
   INICIO
================================= */

console.log("LC HTML Security Scanner iniciado.");
