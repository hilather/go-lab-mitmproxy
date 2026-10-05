import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { APIError } from "../api/client";
import { ProblemBanner } from "./ProblemBanner";

describe("ProblemBanner", () => {
  it("shows API problem detail with code, status, revision and retryable chips plus raw JSON", () => {
    render(
      <ProblemBanner
        error={new APIError({ status: 409, title: "Conflict", detail: "revision changed", code: "revision_conflict", currentRevision: "sha256:abc", retryable: false } as never)}
        fallback="Request failed."
        suffix="Plan again."
      />,
    );
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("revision changed");
    expect(alert).toHaveTextContent("Plan again.");
    expect(alert).toHaveTextContent("code revision_conflict");
    expect(alert).toHaveTextContent("HTTP 409");
    expect(alert).toHaveTextContent("current revision sha256:abc");
    expect(alert).toHaveTextContent("retryable false");
    expect(alert.querySelector("details pre")).not.toBeNull();
  });

  it("shows plain strings and non-API errors without chips or raw JSON", () => {
    const { rerender } = render(<ProblemBanner error="TLS ports must be integers." fallback="x" />);
    expect(screen.getByRole("alert")).toHaveTextContent("TLS ports must be integers.");
    expect(screen.getByRole("alert").querySelector(".chip, details")).toBeNull();
    rerender(<ProblemBanner error={new Error("network down")} fallback="x" />);
    expect(screen.getByRole("alert")).toHaveTextContent("network down");
    rerender(<ProblemBanner error={null} fallback="x" />);
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
