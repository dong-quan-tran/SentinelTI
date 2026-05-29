import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "./App";
import { scoreUrl } from "./api/scanApi";
import { fetchAIExplanation } from "./api/aiApi";
import useModelInfo from "./hooks/useModelInfo";

vi.mock("./api/scanApi", () => ({
  scoreUrl: vi.fn(),
}));

vi.mock("./api/aiApi", () => ({
  fetchAIExplanation: vi.fn(),
}));

vi.mock("./hooks/useModelInfo", () => ({
  default: vi.fn(),
}));

const mockScoreResponse = {
  schema_version: "1.2",
  url: "https://example.com",
  label: 0,
  prob_malicious: 0.08,
  threshold: 0.75,
  heuristic: {
    score: 0.05,
    reasons: [],
  },
  final_label: "benign",
  risk: "low",
  reasons: ["No major indicators found"],
  explanation: {
    summary: "This URL currently appears low risk.",
    why_flagged: "Few suspicious signals were detected.",
    user_action: "Proceed carefully.",
    technical_notes: ["No major indicators found"],
    risk: "low",
    final_label: "benign",
  },
  model_meta: {
    model_type: "xgb",
    threshold: 0.75,
    threshold_source: "metadata",
    recommended_threshold: 0.8,
    recommended_threshold_source: "artifact",
    metrics: {
      roc_auc: 0.99,
      average_precision: 0.98,
    },
    class_labels: {
      benign: 0,
      malicious: 1,
    },
    class_counts: {
      train_0: 10,
      train_1: 5,
      test_0: 4,
      test_1: 2,
    },
    dataset_source: {},
    training_params: {},
    training_notes: [],
    top_features: [],
    model_summary: {
      model_type: "xgb",
      dataset_name: null,
      trained_at: null,
      top_features: [],
    },
  },
};

function setupSuccessfulModelInfo() {
  useModelInfo.mockReturnValue({
    modelInfo: {
      schema_version: "1.1",
      model_meta: mockScoreResponse.model_meta,
    },
    loadingModel: false,
    modelInfoError: "",
  });
}

async function submitUrl(user, url = "https://example.com") {
  const input = screen.getByRole("textbox");
  const submitButton = screen.getByRole("button", {
    name: /scan url|analyze url|check url|submit/i,
  });

  await user.clear(input);
  await user.type(input, url);
  await user.click(submitButton);
}

describe("App AI summary panel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setupSuccessfulModelInfo();
    scoreUrl.mockResolvedValue(mockScoreResponse);
  });

  it("shows the default AI summary empty state after a successful scan", async () => {
    const user = userEvent.setup();
    render(<App />);

    await submitUrl(user);

    expect(await screen.findByText("Scan complete.")).toBeInTheDocument();

    await user.click(
      screen.getByRole("button", { name: /show ai summary/i })
    );

    expect(
      screen.getByText(
        /Generate a plain-language AI summary for this result/i
      )
    ).toBeInTheDocument();
  });

    it("shows loading then renders AI summary content on success", async () => {
    const user = userEvent.setup();
    render(<App />);

    let resolveAI;
    fetchAIExplanation.mockImplementation(
        () =>
        new Promise((resolve) => {
            resolveAI = resolve;
        })
    );

    await submitUrl(user);

    await user.click(
        screen.getByRole("button", { name: /show ai summary/i })
    );

    await user.click(
        screen.getByRole("button", { name: /generate ai summary/i })
    );

    expect(
        await screen.findByText(/Generating a plain-language AI summary/i)
    ).toBeInTheDocument();

    resolveAI({
        deterministic_explanation: mockScoreResponse.explanation,
        ai: {
        summary: "This looks like a low-risk URL.",
        guidance: "The AI summary supports the deterministic verdict.",
        },
    });

    expect(
        await screen.findByText("This looks like a low-risk URL.")
    ).toBeInTheDocument();

    expect(
        screen.getByText("The AI summary supports the deterministic verdict.")
    ).toBeInTheDocument();
    });

  it("shows the disabled/unavailable fallback when AI is unavailable", async () => {
    const user = userEvent.setup();
    render(<App />);

    fetchAIExplanation.mockRejectedValue(
      new Error(
        "AI summary is currently unavailable. Your deterministic verdict is still valid."
      )
    );

    await submitUrl(user);

    await user.click(
      screen.getByRole("button", { name: /show ai summary/i })
    );

    await user.click(
      screen.getByRole("button", { name: /generate ai summary/i })
    );

    expect(
      await screen.findByText("AI summary unavailable")
    ).toBeInTheDocument();

    expect(
      screen.getByText(
        /AI-assisted explanations are turned off or temporarily unavailable right now/i
      )
    ).toBeInTheDocument();

    expect(
      screen.getByText(
        /You can still rely on the deterministic verdict, explanation, and detailed reasons shown above/i
      )
    ).toBeInTheDocument();
  });

  it("shows the generation failure fallback when AI generation fails", async () => {
    const user = userEvent.setup();
    render(<App />);

    fetchAIExplanation.mockRejectedValue(
      new Error(
        "AI summary could not be generated right now. Your deterministic verdict is still valid."
      )
    );

    await submitUrl(user);

    await user.click(
      screen.getByRole("button", { name: /show ai summary/i })
    );

    await user.click(
      screen.getByRole("button", { name: /generate ai summary/i })
    );

    expect(
      await screen.findByText("AI summary unavailable")
    ).toBeInTheDocument();

    expect(
      screen.getByText(
        /The AI rewrite could not be generated for this scan, but the deterministic result is still complete/i
      )
    ).toBeInTheDocument();
  });

  it("clears stale AI summary state when a new scan starts", async () => {
    const user = userEvent.setup();
    render(<App />);

    fetchAIExplanation.mockResolvedValue({
      deterministic_explanation: mockScoreResponse.explanation,
      ai: {
        summary: "This looks like a low-risk URL.",
        guidance: "The deterministic verdict remains primary.",
      },
    });

    await submitUrl(user, "https://example.com");

    await user.click(
      screen.getByRole("button", { name: /show ai summary/i })
    );

    await user.click(
      screen.getByRole("button", { name: /generate ai summary/i })
    );

    expect(
      await screen.findByText("This looks like a low-risk URL.")
    ).toBeInTheDocument();

    scoreUrl.mockResolvedValueOnce({
      ...mockScoreResponse,
      url: "https://second-example.com",
    });

    await submitUrl(user, "https://second-example.com");

    expect(await screen.findByText("Scan complete.")).toBeInTheDocument();

    await user.click(
      screen.getByRole("button", { name: /show ai summary/i })
    );

    expect(
      screen.getByText(
        /Generate a plain-language AI summary for this result/i
      )
    ).toBeInTheDocument();

    expect(
      screen.queryByText("This looks like a low-risk URL.")
    ).not.toBeInTheDocument();
  });

  it("renders the AI panel as a polite live region when expanded", async () => {
    const user = userEvent.setup();
    render(<App />);

    await submitUrl(user);

    await user.click(
      screen.getByRole("button", { name: /show ai summary/i })
    );

    const panel = screen.getByRole("status");
    expect(panel).toHaveAttribute("aria-live", "polite");
    expect(panel).toHaveAttribute("aria-atomic", "true");
  });
});