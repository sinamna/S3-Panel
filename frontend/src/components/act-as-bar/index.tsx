import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronDown, UserRoundSearch } from 'lucide-react'

import { clearActAs, fetchActAs, setActAs } from '@/api/panel'
import { Button } from '@/components/shadcn/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger
} from '@/components/shadcn/dropdown-menu'
import usePanelSession from '@/hooks/usePanelSession'
import { t } from '@/i18n'

/**
 * Lets an admin act as an IAM debug user (IAM proposal 008), and shows a
 * banner while they do. Renders nothing for anyone IAM does not offer it to.
 */
const ActAsBar = () => {
  const queryClient = useQueryClient()
  const bootstrap = usePanelSession(s => s.bootstrap)
  const { data } = useQuery({ queryKey: ['act-as'], queryFn: fetchActAs })

  if (!data?.available) return null

  const switchTo = async (email: string | null) => {
    if (email) await setActAs(email)
    else await clearActAs()
    // Everything on screen was fetched as the previous identity.
    await queryClient.invalidateQueries()
    await bootstrap()
  }

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-sky-200 bg-sky-50 px-4 py-2 text-sm text-sky-900">
      <span>
        {data.acting
          ? `${t('acting_as')} ${data.acting} — ${t('acting_as_hint')}`
          : t('act_as_hint')}
      </span>
      <div className="flex gap-2">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="sm" className="gap-1">
              <UserRoundSearch className="size-4" />
              {t('act_as_debug_user')}
              <ChevronDown className="size-3" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            {data.candidates.length === 0 ? (
              <DropdownMenuItem disabled>
                {t('no_debug_users')}
              </DropdownMenuItem>
            ) : (
              data.candidates.map(u => (
                <DropdownMenuItem
                  key={u.email}
                  onSelect={() => void switchTo(u.email)}
                >
                  {u.email}
                </DropdownMenuItem>
              ))
            )}
          </DropdownMenuContent>
        </DropdownMenu>
        {data.acting ? (
          <Button size="sm" variant="ghost" onClick={() => void switchTo(null)}>
            {t('stop_acting')}
          </Button>
        ) : null}
      </div>
    </div>
  )
}

export default ActAsBar
