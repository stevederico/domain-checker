import { useEffect, useState, useCallback } from 'react';
import { getState } from '@stevederico/skateboard-ui/Context';
import { useSafeNavigate } from '@stevederico/skateboard-ui/Utilities';
import {
  Command,
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
} from '@stevederico/skateboard-ui/ui/command';
import { Circle, Search } from '../icons';

const PAGE_ICONS: Record<string, typeof Search> = { search: Search };

interface PageEntry {
  title: string;
  url: string;
  icon: string;
}

export default function CommandMenu() {
  const [open, setOpen] = useState(false);
  const navigate = useSafeNavigate();
  const { state } = getState();
  const pages: PageEntry[] = state.constants?.pages || [];

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    }

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleSelect = useCallback(
    (url: string) => {
      navigate(`/app/${url}`);
      setOpen(false);
    },
    [navigate]
  );

  return (
    <CommandDialog
      open={open}
      onOpenChange={setOpen}
      title="Command Menu"
      description="Search and navigate to any page"
    >
      <Command className="rounded-lg">
        <CommandInput placeholder="Search pages..." />
        <CommandList className="p-2">
          <CommandEmpty>No pages found.</CommandEmpty>
          <CommandGroup heading="Pages">
            {pages.map((page) => (
              <CommandItem
                key={page.url}
                value={page.title}
                onSelect={() => handleSelect(page.url)}
                className="gap-3 px-3 py-2.5"
              >
                {(() => {
                  const Icon = PAGE_ICONS[page.icon] ?? Circle;
                  return <Icon size={16} aria-hidden="true" className="shrink-0 text-muted-foreground" />;
                })()}
                <span>{page.title}</span>
              </CommandItem>
            ))}
          </CommandGroup>
        </CommandList>
      </Command>
    </CommandDialog>
  );
}
