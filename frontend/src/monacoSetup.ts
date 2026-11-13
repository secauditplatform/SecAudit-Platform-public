/** Bundle Monaco locally so air-gapped CSP can stay on 'self' (no jsDelivr). */
import { loader } from "@monaco-editor/react";
import * as monaco from "monaco-editor";

loader.config({ monaco });
