import gradio as gr
import pandas as pd
from features import classify_url

# Single URL prediction
def predict_single(url: str):
    try:
        label, score, reasons, attack_types, prevention_tips, osi_layers = classify_url(url)
        return (
            f"{label} (score={score})",
            "\n".join(reasons) if reasons else "No suspicious signs.",
            attack_types,
            prevention_tips,
            osi_layers
        )
    except Exception as e:
        return (f"ERROR: {e}", "N/A", "N/A", "N/A", "N/A")

# CSV batch prediction
def predict_file(file_obj):
    try:
        df = pd.read_csv(file_obj)
    except Exception as e:
        return pd.DataFrame([["ERROR reading file", "", "", "", "", str(e)]],
                            columns=["URL", "Result", "Reasons", "Attack Types", "Prevention", "OSI Layer"])

    results = []
    for url in df.iloc[:, 0].astype(str).tolist():
        label, score, reasons, attack_types, prevention_tips, osi_layers = classify_url(url)
        results.append([
            url,
            f"{label} (score={score})",
            "; ".join(reasons) if reasons else "No suspicious signs.",
            attack_types,
            prevention_tips,
            osi_layers
        ])

    return pd.DataFrame(results, columns=["URL", "Result", "Reasons", "Attack Types", "Prevention", "Layer"])

# Gradio interface
with gr.Blocks() as demo:
    gr.Markdown("# 🚨 Malicious URL Detector — Heuristic")
    gr.Markdown("Check a single URL or upload a CSV. This detector uses simple rules (no ML).")

    with gr.Tab("Single URL Check"):
        with gr.Row():
            url_in = gr.Textbox(label="Enter URL", placeholder="http://example.com/login")
            btn = gr.Button("Check")
        out_label = gr.Textbox(label="Result")
        out_reasons = gr.Textbox(label="Reasons")
        out_attack = gr.Textbox(label="Attack Types")
        out_prevention = gr.Textbox(label="Prevention")
        out_layer = gr.Textbox(label="Layer")
        btn.click(
            fn=predict_single,
            inputs=url_in,
            outputs=[out_label, out_reasons, out_attack, out_prevention, out_layer]
        )

    with gr.Tab("Batch CSV Check"):
        file_in = gr.File(file_types=[".csv"], file_count="single", label="Upload CSV")
        file_out = gr.Dataframe(headers=["URL", "Result", "Reasons", "Attack Types", "Prevention", "Layer"], type="pandas")
        download_btn = gr.File(label="Download Results")

        def batch_with_download(file_obj):
            df = predict_file(file_obj)
            output_path = "results.csv"
            df.to_csv(output_path, index=False)
            return df, output_path

        file_in.upload(fn=batch_with_download, inputs=file_in, outputs=[file_out, download_btn])

if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=8080)
