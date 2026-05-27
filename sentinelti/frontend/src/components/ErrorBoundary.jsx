import React from "react";

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    console.error("ErrorBoundary caught an error:", error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-boundary-card" role="alert">
          <h3>Something went wrong in this section.</h3>
          <p>
            The rest of SentinelTI is still available. You can try scanning again
            or reset this panel.
          </p>
          <button
            type="button"
            className="secondary-button"
            onClick={this.handleReset}
          >
            Reset panel
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}