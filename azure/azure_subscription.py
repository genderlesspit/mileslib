from context import milescontext as mc
from util import milesutil as mu

class AzureSubscription:
    """
    Handles Azure Subscription ID selection, validation, and caching.

    Uses project-scoped key: <project>.AZURE_SUBSCRIPTION_ID
    """

    @staticmethod
    def init(project: str) -> str:
        """
        Prompts the user to choose a subscription if multiple exist,
        then stores and validates the selected subscription ID.

        Args:
            project (str): Project scope.

        Returns:
            str: Validated subscription ID.
        """
        print(f"[AzureSubscription] Fetching available subscriptions...")
        subs = AzureSubscription._get_all()

        if not subs:
            raise RuntimeError("[AzureSubscription] No subscriptions found. Are you logged in to Azure?")

        if len(subs) == 1:
            sub = subs[0]
            print(f"[AzureSubscription] One subscription found: {sub['name']} ({sub['id']})")
        else:
            print("\n🔢 Choose a subscription:")
            for i, s in enumerate(subs, 1):
                print(f" {i}. {s['name']} ({s['id']})")
            print()

            while True:
                try:
                    idx = int(input(f"Enter number (1–{len(subs)}): ").strip()) - 1
                    if 0 <= idx < len(subs):
                        sub = subs[idx]
                        break
                except Exception:
                    pass
                print("❌ Invalid input. Try again.")

        sub_id = sub["id"]
        key = f"{project}.AZURE_SUBSCRIPTION_ID"
        mc.env.write(key, sub_id, replace_existing=True)

        cfg_root = mc.env.get(f"{project}.config_dir", required=True)
        mc.cfg.write(cfg_root, set={
            "aad": {
                "AZURE_SUBSCRIPTION_ID": sub_id
            }
        })

        print(f"[AzureSubscription] Subscription set: {sub['name']} ({sub_id})")
        return sub_id

    @staticmethod
    def get(project: str) -> str:
        """
        Retrieves the project’s subscription ID or triggers selection.

        Args:
            project (str): Project name.

        Returns:
            str: Subscription ID
        """
        key = f"{project}.AZURE_SUBSCRIPTION_ID"
        sub_id = mc.env.get(key, required=False)
        if not sub_id:
            return AzureSubscription.init(project)

        AzureSubscription.validate(sub_id)
        return sub_id

    @staticmethod
    def validate(sub_id: str) -> bool:
        """
        Verifies the subscription ID exists in the current Azure context.

        Args:
            sub_id (str): Azure subscription ID

        Returns:
            bool: True if valid; raises if invalid
        """
        subs = AzureSubscription._get_all()
        valid_ids = [s["id"] for s in subs]
        if sub_id not in valid_ids:
            raise ValueError(f"[AzureSubscription] Subscription ID not recognized: {sub_id}")
        return True

    @staticmethod
    def _get_all() -> list[dict]:
        """
        Returns a list of all available Azure subscriptions.

        Returns:
            list of dicts with 'id' and 'name'
        """
        raw = mu.run(
            ["az", "account", "list", "--output", "json"],
            capture_output=True, text=True, check=True, force_global_shell=True
        ).stdout
        import json
        return json.loads(raw)

    @staticmethod
    def help():
        """
        Prints CLI guidance on managing Azure subscriptions.
        """
        print("\n[🔧 Azure Subscription Help]")
        print("────────────────────────────")
        print("1. Sign in with: `az login`")
        print("2. See subscriptions: `az account list --output table`")
        print("3. Set a default: `az account set --subscription <id>`")
        print("────────────────────────────\n")
