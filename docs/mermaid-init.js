(function () {
  const MERMAID_URL =
    "https://cdn.jsdelivr.net/npm/mermaid@10.9.3/dist/mermaid.esm.min.mjs";

  async function renderMermaid() {
    const blocks = Array.from(
      document.querySelectorAll("pre > code.language-mermaid"),
    );
    if (blocks.length === 0) {
      return;
    }

    try {
      const mermaidModule = await import(MERMAID_URL);
      const mermaid = mermaidModule.default;

      mermaid.initialize({
        startOnLoad: false,
        securityLevel: "strict",
        theme: "base",
        themeVariables: {
          background: "transparent",
          fontFamily:
            "Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif",
          primaryColor: "#0f172a",
          primaryTextColor: "#e5e7eb",
          primaryBorderColor: "#22d3ee",
          secondaryColor: "#134e4a",
          secondaryTextColor: "#e5e7eb",
          secondaryBorderColor: "#2dd4bf",
          tertiaryColor: "#1e293b",
          tertiaryTextColor: "#e5e7eb",
          tertiaryBorderColor: "#64748b",
          lineColor: "#94a3b8",
          edgeLabelBackground: "#0f172a",
          clusterBkg: "#111827",
          clusterBorder: "#475569",
        },
      });

      for (const block of blocks) {
        const pre = block.parentElement;
        if (!pre) {
          continue;
        }

        const wrapper = document.createElement("div");
        wrapper.className = "nyx-mermaid";

        const diagram = document.createElement("div");
        diagram.className = "mermaid";
        diagram.textContent = block.textContent.trim();

        wrapper.appendChild(diagram);
        pre.replaceWith(wrapper);
      }

      await mermaid.run({ querySelector: ".nyx-mermaid .mermaid" });
    } catch (error) {
      console.warn("Mermaid rendering failed", error);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", renderMermaid);
  } else {
    renderMermaid();
  }
})();
