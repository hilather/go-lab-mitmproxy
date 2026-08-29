import { useParams } from "react-router-dom";
import { FlowInspector } from "./FlowInspector";

export function FlowPage() {
  const { id = "" } = useParams();
  if (id === "") {
    return null;
  }
  return <FlowInspector id={id} />;
}
