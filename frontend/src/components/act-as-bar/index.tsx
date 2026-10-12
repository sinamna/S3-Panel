import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronDown, UserRoundSearch } from 'lucide-react'
import { useState } from 'react'

import { clearActAs, fetchActAs, setActAs } from '@/api/panel'
import { Button } from '@/components/shadcn/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger
} from '@/components/shadcn/dropdown-menu'
import { useToast } from '@/hooks/use-toast'
import usePanelSession from '@/hooks/usePanelSession'
import { t } from '@/i18n'
import type { HTTPClientError } from '@/services/http/interceptorsConfig'

/**
 * Lets an admin act as an IAM debug user (IAM proposal 008), and shows a
 * banner while they do. Renders nothing for anyone IAM does not offer it to.
 */
const ActAsBar = () => {
  const queryClient = useQueryClient()
  const bootstrap = usePanelSession(s => s.bootstrap)
  const { toast } = useToast()
  const [pending, setPending] = useState(false)
  const { data } = useQuery({ queryKey: ['act-as'], queryFn: fetchActAs })

  if (!data?.available) return null

  const switchTo = async (email: string | null) => {
    setPending(true)
    try {
      if (email) await setActAs(email)
      else await clearActAs()
    } catch (err) {
      toast({
        variant: 'destructive',
        title:
          (err as HTTPClientError<{ message?: string }>).response?.data
            ?.message || t('act_as_failed')
      })
    } finally {
      // Runs after any attempt, so a failed switch or a failed refresh cannot
      // leave the screen on the previous identity. Session first, so the
      // refetched lists see the new identity rather than the old one.
      try {
        await bootstrap()
        // Everything on screen was fetched as the previous identity.
        await queryClient.invalidateQueries()
      } finally {
        setPending(false)
      }
    }
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
            <Button
              variant="outline"
              size="sm"
              className="gap-1"
              disabled={pending}
            >
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
                  disabled={pending}
                  onSelect={() => void switchTo(u.email)}
                >
                  {u.email}
                </DropdownMenuItem>
              ))
            )}
          </DropdownMenuContent>
        </DropdownMenu>
        {data.acting ? (
          <Button
            size="sm"
            variant="ghost"
            disabled={pending}
            onClick={() => void switchTo(null)}
          >
            {t('stop_acting')}
          </Button>
        ) : null}
      </div>
    </div>
  )
}

export default ActAsBar
