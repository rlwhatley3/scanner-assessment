import { NavLink } from "react-router-dom";
import "./style.css";

export default function ApplicationNavigation() {
  return (
    <header className="app-navbar">
      <NavLink className="brand" to="/instructions">
        <span className="brand-mark" aria-hidden="true" />
        Secrets Scanner Playground
      </NavLink>
      <nav className="nav-links" aria-label="Application views">
        <NavLink className="tab" to="/instructions">
          Instructions
        </NavLink>
        <NavLink className="tab" to="/whiteboard">
          Whiteboard
        </NavLink>
        <NavLink className="tab" to="/playground">
          Playground
        </NavLink>
        <NavLink className="tab" to="/submission">
          Submission
        </NavLink>
        <span className="nav-separator" aria-hidden="true" />
        <NavLink className="tab" to="/api-docs">
          API Docs
        </NavLink>
      </nav>
    </header>
  );
}
