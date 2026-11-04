export type Child = Node | string;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className = "",
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== undefined) {
    node.textContent = text;
  }
  return node;
}

export function append(parent: Node, ...children: Child[]): void {
  for (const child of children) {
    parent.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
  }
}

