import { Link } from "react-router-dom";
import "./style.css";

export default function PlaygroundView() {
  return (
    <main className="page-content">
      <section className="panel instructions-intro playground-intro">
        <h1>Secrets Scanner Playground</h1>
        <p className="intro">
          Build the scanner experience described in the{" "}
          <Link className="internal-link" to="/instructions">
            Instructions
          </Link>{" "}
          page.
        </p>
        <div className="starter">
          <span className="status" aria-hidden="true" />
          <div>
            <h2>Starter is running</h2>
            <p>
              The Vite frontend and Rust API are ready. The scanning behavior is yours to design and
              implement.
            </p>
          </div>
        </div>
      </section>
    </main>
  );
}
