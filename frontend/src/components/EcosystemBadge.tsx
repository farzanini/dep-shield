
interface Props {
  ecosystem: string;
  className?: string;
}

// Mapping from Go models.Ecosystem strings to display metadata.
const ECOSYSTEMS: Record<
  string,
  { label: string; icon: string; bg: string; text: string }
> = {
  npm: {
    label: 'npm',
    icon: 'N',
    bg: 'bg-red-950',
    text: 'text-red-300',
  },
  Go: {
    label: 'Go',
    icon: '🐹',
    bg: 'bg-cyan-950',
    text: 'text-cyan-300',
  },
  'crates.io': {
    label: 'Cargo',
    icon: '⚙',
    bg: 'bg-orange-950',
    text: 'text-orange-300',
  },
  PyPI: {
    label: 'PyPI',
    icon: '🐍',
    bg: 'bg-yellow-950',
    text: 'text-yellow-300',
  },
  RubyGems: {
    label: 'Ruby',
    icon: '💎',
    bg: 'bg-pink-950',
    text: 'text-pink-300',
  },
};

const FALLBACK = {
  label: (eco: string) => eco,
  icon: '📦',
  bg: 'bg-gray-800',
  text: 'text-gray-400',
};

export default function EcosystemBadge({ ecosystem, className = '' }: Props) {
  const meta = ECOSYSTEMS[ecosystem];

  const bg   = meta?.bg   ?? FALLBACK.bg;
  const text = meta?.text ?? FALLBACK.text;
  const icon = meta?.icon ?? FALLBACK.icon;
  const label = meta?.label ?? FALLBACK.label(ecosystem);

  return (
    <span
      className={[
        'inline-flex items-center gap-1 rounded px-1.5 py-0.5',
        'text-xs font-medium',
        bg,
        text,
        className,
      ].join(' ')}
      title={ecosystem}
    >
      <span aria-hidden="true">{icon}</span>
      {label}
    </span>
  );
}
