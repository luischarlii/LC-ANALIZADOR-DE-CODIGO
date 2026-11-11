"use strict";

/*
  LC HTML Security Scanner
  Análisis estático local de HTML
*/

const htmlInput = document.getElementById("htmlInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const clearBtn = document.getElementById("clearBtn");

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


/* =========================
   REGLAS DE DETECCIÓN
========================= */

const RULES = [

  {
    id: "eval",
    title: "Uso de eval()",
    level: "critical",
    points: 30,
    pattern: /\beval\s*\(/gi,
    description:
      "eval() puede ejecutar código construido dinámicamente y dificulta determinar qué código terminará ejecutándose."
  },

  {
    id: "function",
    title: "Constructor Function()",
    level: "critical",
    points: 30,
    pattern: /\bnew\s+Function\s*\(/gi,
    description:
      "El constructor Function() permite crear código JavaScript dinámicamente."
  },

  {
    id: "javascript-url",
    title: "URL javascript:",
    level: "critical",
    points: 30,
    pattern: /\bjavascript\s*:/gi,
    description:
      "Se encontró un esquema javascript: que puede ejecutar código desde una URL o atributo."
  },

  {
    id: "iframe",
    title: "Iframe externo",
    level: "medium",
    points: 10,
    pattern: /<iframe\b[^>]*\bsrc\s*=\s*["'][^"']+/gi,
    description:
      "Un iframe puede cargar contenido externo dentro de la aplicación."
  },

  {
    id: "external-script",
    title: "Script externo",
    level: "medium",
    points: 12,
    pattern: /<script\b[^>]*\bsrc\s*=\s*["']https?:\/\//gi,
    description:
      "El HTML carga JavaScript desde un servidor externo."
  },

  {
    id: "fetch",
    title: "Solicitud fetch()",
    level: "medium",
    points: 8,
    pattern: /\bfetch\s*\(/gi,
    description:
      "Se detectó una solicitud HTTP mediante fetch(). Revisa el destino y los datos enviados."
  },

  {
    id: "xhr",
    title: "XMLHttpRequest",
    level: "medium",
    points: 8,
    pattern: /\bXMLHttpRequest\b/gi,
    description:
      "Se detectó comunicación HTTP mediante XMLHttpRequest."
  },

  {
    id: "websocket",
    title: "WebSocket",
    level: "medium",
    points: 8,
    pattern: /\bWebSocket\s*\(/gi,
    description:
      "Se detectó una conexión WebSocket."
  },

  {
    id: "storage",
    title: "Acceso a almacenamiento",
    level: "low",
    points: 3,
    pattern: /\b(localStorage|sessionStorage)\b/gi,
    description:
      "El código utiliza almacenamiento del navegador."
  },

  {
    id: "cookies",
    title: "Acceso a cookies",
    level: "high",
    points: 15,
    pattern: /\bdocument\.cookie\b/gi,
    description:
      "El código intenta acceder a cookies del navegador."
  },

  {
    id: "location",
    title: "Manipulación de ubicación",
    level: "high",
    points: 12,
    pattern: /\b(window\.location|location\.href|location\.replace|location\.assign)\b/gi,
    description:
      "Se detectó código capaz de cambiar o redirigir la ubicación del navegador."
  },

  {
    id: "window-open",
    title: "Apertura de ventanas",
    level: "medium",
    points: 7,
    pattern: /\bwindow\.open\s*\(/gi,
    description:
      "El código puede abrir una nueva ventana o pestaña."
  },

  {
    id: "innerhtml",
    title: "Uso de innerHTML",
    level: "medium",
    points: 7,
    pattern: /\binnerHTML\b/gi,
    description:
      "innerHTML puede introducir contenido HTML dinámico y debe revisarse cuando recibe datos externos."
  },

  {
    id: "document-write",
    title: "document.write()",
    level: "medium",
    points: 8,
    pattern: /\bdocument\.write\s*\(/gi,
    description:
      "document.write() modifica directamente el documento y puede ser problemático cuando recibe contenido externo."
  },

  {
    id: "dynamic-timer",
    title: "Código dinámico en temporizador",
    level: "high",
    points: 15,
    pattern: /\b(setTimeout|setInterval)\s*\(\s*["'`]/gi,
    description:
      "Se detectó código JavaScript pasado como texto a un temporizador."
  },

  {
    id: "event-handler",
    title: "Event handler inline",
    level: "low",
    points: 3,
    pattern: /\bon(load|error|click|mouseover|focus|submit|change)\s*=/gi,
    description:
      "Se encontró un manejador de eventos JavaScript directamente dentro del HTML."
  },

  {
    id: "form-external",
    title: "Formulario externo",
    level: "high",
    points: 15,
    pattern: /<form\b[^>]*\baction\s*=\s*["']https?:\/\//gi,
    description:
      "Un formulario envía datos directamente hacia una dirección HTTP/HTTPS."
  },

  {
    id: "meta-refresh",
    title: "Redirección automática",
    level: "high",
    points: 15,
    pattern: /<meta\b[^>]*http-equiv\s*=\s*["']refresh["']/gi,
    description:
      "Se detectó una redirección automática mediante meta refresh."
  },

  {
    id: "base64",
    title: "Posible código Base64",
    level: "medium",
    points: 10,
    pattern: /\b(atob|btoa)\s*\(/gi,
    description:
      "Se detectó conversión Base64. Puede ser legítima, pero también se utiliza para ocultar datos o código."
  },

  {
    id: "obfuscation",
    title: "Posible ofuscación",
    level: "high",
    points: 15,
    pattern: /\b(String\.fromCharCode|unescape|decodeURIComponent)\s*\(/gi,
    description:
      "Se detectó una función utilizada frecuentemente en técnicas de transformación u ofuscación."
  }

];


/* =========================
   UTILIDADES
========================= */

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
  const lines = text.split("\n");

  const lineNumber =
    getLineNumber(text, index);

  return lines[lineNumber - 1] || "";
}


/* =========================
   ANALIZADOR
========================= */

function analyzeHTML(html) {

  const findings = [];
  let score = 0;

  for (const rule of RULES) {

    const regex = new RegExp(
      rule.pattern.source,
      rule.pattern.flags
    );

    let match;

    while ((match = regex.exec(html)) !== null) {

      const index = match.index;

      findings.push({
        id: rule.id,
        title: rule.title,
        level: rule.level,
        points: rule.points,
        description: rule.description,
        line: getLineNumber(html, index),
        code: getLine(html, index).trim()
      });

      score += rule.points;

      /*
        Evita que una misma regla genere
        cientos de puntos por repetición.
      */
      if (findings.filter(f => f.id === rule.id).length >= 3) {
        break;
      }
    }
  }


  /* Detectar scripts inline */

  const inlineScripts =
    html.match(/<script\b(?![^>]*\bsrc\s*=)[^>]*>/gi);

  if (inlineScripts && inlineScripts.length > 0) {

    findings.push({
      id: "inline-script",
      title: "JavaScript inline",
      level: "low",
      points: 3,
      description:
        "El documento contiene JavaScript directamente dentro del HTML.",
      line: 1,
      code: inlineScripts[0]
    });

    score += 3;
  }


  /* Detectar URLs externas */

  const externalURLs =
    html.match(/https?:\/\/[^\s"'<>]+/gi);

  if (externalURLs && externalURLs.length > 0) {

    const uniqueURLs =
      [...new Set(externalURLs)];

    findings.push({
      id: "external-url",
      title: "Recursos externos detectados",
      level: "medium",
      points: Math.min(uniqueURLs.length * 2, 10),
      description:
        `Se detectaron ${uniqueURLs.length} URL(s) externas en el código.`,
      line: 1,
      code: uniqueURLs.slice(0, 3).join(" | ")
    });

    score += Math.min(uniqueURLs.length * 2, 10);
  }


  score = Math.min(score, 100);

  return {
    score,
    findings
  };
}


/* =========================
   NIVEL DE RIESGO
========================= */

function getRisk(score) {

  if (score === 0) {
    return {
      title: "Sin amenazas detectadas",
      description:
        "No se encontraron patrones relevantes en el análisis.",
      label: "SEGURO",
      className: "level-low"
    };
  }

  if (score <= 20) {
    return {
      title: "Riesgo bajo",
      description:
        "Se encontraron algunos elementos que conviene revisar.",
      label: "BAJO",
      className: "level-low"
    };
  }

  if (score <= 45) {
    return {
      title: "Riesgo medio",
      description:
        "Hay patrones que requieren revisión antes de ejecutar el HTML.",
      label: "MEDIO",
      className: "level-medium"
    };
  }

  if (score <= 70) {
    return {
      title: "Riesgo alto",
      description:
        "Se encontraron varios indicadores potencialmente peligrosos.",
      label: "ALTO",
      className: "level-high"
    };
  }

  return {
    title: "Riesgo crítico",
    description:
      "Se encontraron múltiples indicadores que requieren revisión inmediata.",
    label: "CRÍTICO",
    className: "level-critical"
  };
}


/* =========================
   MOSTRAR RESULTADOS
========================= */

function showResults(result) {

  const risk = getRisk(result.score);

  resultSection.classList.remove("hidden");

  riskTitle.textContent = risk.title;

  riskDescription.textContent =
    risk.description;

  riskBadge.textContent =
    risk.label;

  riskBadge.className =
    "risk-badge " + risk.className;

  riskScore.textContent =
    `${result.score}/100`;

  scoreBar.style.width =
    `${result.score}%`;

  scoreBar.style.background =
    result.score === 0
      ? "var(--safe)"
      : result.score <= 20
        ? "var(--safe)"
        : result.score <= 45
          ? "var(--medium)"
          : result.score <= 70
            ? "var(--high)"
            : "var(--critical)";


  /* Contadores */

  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };

  for (const finding of result.findings) {
    counts[finding.level]++;
  }

  criticalCount.textContent =
    counts.critical;

  highCount.textContent =
    counts.high;

  mediumCount.textContent =
    counts.medium;

  lowCount.textContent =
    counts.low;


  /* Lista */

  findingsList.innerHTML = "";

  if (result.findings.length === 0) {

    findingsList.innerHTML = `
      <div class="finding">
        <div class="finding-title">
          ✅ No se encontraron patrones sospechosos
        </div>

        <div class="finding-description">
          El análisis estático no encontró reglas
          activadas por el código proporcionado.
        </div>
      </div>
    `;

    return;
  }


  result.findings.forEach((finding) => {

    const item =
      document.createElement("div");

    item.className = "finding";

    item.innerHTML = `
      <div class="finding-top">

        <div class="finding-title">
          ${escapeHTML(finding.title)}
        </div>

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

      <code class="finding-code">
        ${escapeHTML(finding.code)}
      </code>
    `;

    findingsList.appendChild(item);
  });
}


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


/* =========================
   EVENTOS
========================= */

analyzeBtn.addEventListener("click", () => {

  const html =
    htmlInput.value.trim();

  if (!html) {

    alert("Pega primero un código HTML para analizar.");

    htmlInput.focus();

    return;
  }

  const result =
    analyzeHTML(html);

  showResults(result);

  resultSection.scrollIntoView({
    behavior: "smooth",
    block: "start"
  });
});


clearBtn.addEventListener("click", () => {

  htmlInput.value = "";

  resultSection.classList.add("hidden");

  findingsList.innerHTML = "";

  htmlInput.focus();
});
