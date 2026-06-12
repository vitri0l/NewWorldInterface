#include "VADTreeWalker.h"

// =================================================================
// VAD AVL TREE â€” FIELD ACCESSORS
// All offsets are byte offsets from the MMVAD node base address.
// Balance encoding (bits [1:0] of ParentValue):
//   0 = balanced  1 = right-heavy (+1)  2 = left-heavy (-1)
// =================================================================

static __forceinline PVOID VadGetChild(PVOID node, DWORD off) {
	return *(PVOID*)((ULONG_PTR)node + off);
}
static __forceinline VOID VadSetChild(PVOID node, DWORD off, PVOID child) {
	*(PVOID*)((ULONG_PTR)node + off) = child;
}
static __forceinline PVOID VadGetParent(PVOID node, DWORD parentOff) {
	return (PVOID)(*(ULONG_PTR*)((ULONG_PTR)node + parentOff) & ~(ULONG_PTR)0x3);
}
static __forceinline ULONG VadGetBalance(PVOID node, DWORD parentOff) {
	return (ULONG)(*(ULONG_PTR*)((ULONG_PTR)node + parentOff) & 0x3);
}
static __forceinline VOID VadSetParentBalance(PVOID node, DWORD parentOff, PVOID parent, ULONG balance) {
	*(ULONG_PTR*)((ULONG_PTR)node + parentOff) = (ULONG_PTR)parent | (balance & 0x3);
}
// StartingVpn is spread across two locations (same layout as WalkVADIterative)
static __forceinline unsigned long long VadGetStartingVpn(PVOID node, DWORD startOff) {
	unsigned long long qw = *(unsigned long long*)((ULONG_PTR)node + startOff);
	unsigned long long hi = *(unsigned long long*)((ULONG_PTR)node + 0x20);
	return (qw & 0xFFFFFFFF) | ((hi & 0xFF) << 32);
}

// =================================================================
// VAD AVL TREE â€” STRUCTURAL ROTATIONS
// newXBalance    : balance assigned to the node rotating down  (x)
// newRootBalance : balance assigned to the new subtree root
// =================================================================

static VOID VadRotateLeft(PVOID x, DWORD LeftOff, DWORD RightOff, DWORD ParentOff,
	PVOID* pRoot, ULONG newXBalance, ULONG newRootBalance) {
	PVOID r = VadGetChild(x, RightOff);
	PVOID b = VadGetChild(r, LeftOff);
	PVOID p = VadGetParent(x, ParentOff);

	VadSetChild(x, RightOff, b);
	if (b) VadSetParentBalance(b, ParentOff, x, VadGetBalance(b, ParentOff));

	VadSetParentBalance(r, ParentOff, p, newRootBalance);
	if      (p == NULL)                    *pRoot = r;
	else if (VadGetChild(p, LeftOff) == x) VadSetChild(p, LeftOff,  r);
	else                                   VadSetChild(p, RightOff, r);

	VadSetChild(r, LeftOff, x);
	VadSetParentBalance(x, ParentOff, r, newXBalance);
}

static VOID VadRotateRight(PVOID x, DWORD LeftOff, DWORD RightOff, DWORD ParentOff,
	PVOID* pRoot, ULONG newXBalance, ULONG newRootBalance) {
	PVOID l = VadGetChild(x, LeftOff);
	PVOID b = VadGetChild(l, RightOff);
	PVOID p = VadGetParent(x, ParentOff);

	VadSetChild(x, LeftOff, b);
	if (b) VadSetParentBalance(b, ParentOff, x, VadGetBalance(b, ParentOff));

	VadSetParentBalance(l, ParentOff, p, newRootBalance);
	if      (p == NULL)                    *pRoot = l;
	else if (VadGetChild(p, LeftOff) == x) VadSetChild(p, LeftOff,  l);
	else                                   VadSetChild(p, RightOff, l);

	VadSetChild(l, RightOff, x);
	VadSetParentBalance(x, ParentOff, l, newXBalance);
}

// =================================================================
// VAD AVL TREE â€” INSERT REBALANCING  (bottom-up from inserted node)
// Rotation during insert always restores subtree height â†’ stop after any rotation.
// All locals are declared at the top of each block to stay C89-compatible.
// =================================================================

static VOID VadRebalanceInsert(PVOID inserted, DWORD LeftOff, DWORD RightOff,
	DWORD ParentOff, PVOID* pRoot) {
	PVOID   node;
	PVOID   parent;
	PVOID   gp;
	ULONG   pBal;
	BOOLEAN isLeft;
	ULONG   nBal;
	PVOID   m;
	ULONG   mBal;
	ULONG   newNodeBal;
	ULONG   newParentBal;

	node   = inserted;
	parent = VadGetParent(node, ParentOff);

	while (parent != NULL) {
		gp     = VadGetParent(parent, ParentOff);
		pBal   = VadGetBalance(parent, ParentOff);
		isLeft = (VadGetChild(parent, LeftOff) == node);

		if (isLeft) {
			if (pBal == 1) {
				// right-heavy â†’ balanced, height unchanged â€” stop
				VadSetParentBalance(parent, ParentOff, gp, 0);
				break;
			}
			if (pBal == 0) {
				// balanced â†’ left-heavy, height grew â€” continue up
				VadSetParentBalance(parent, ParentOff, gp, 2);
				node = parent; parent = gp;
				continue;
			}
			// pBal == 2: left-heavy â†’ rotation required
			nBal = VadGetBalance(node, ParentOff);
			if (nBal == 2) {
				// LL â€” single right rotation, both nodes become balanced
				VadRotateRight(parent, LeftOff, RightOff, ParentOff, pRoot, 0, 0);
			} else {
				// LR â€” rotate node left then parent right
				// Middle node M's old balance determines new balances
				m          = VadGetChild(node, RightOff);
				mBal       = VadGetBalance(m, ParentOff);
				newNodeBal   = (mBal == 1) ? 2 : 0;
				newParentBal = (mBal == 2) ? 1 : 0;
				VadRotateLeft (node,   LeftOff, RightOff, ParentOff, pRoot, newNodeBal,   0);
				VadRotateRight(parent, LeftOff, RightOff, ParentOff, pRoot, newParentBal, 0);
			}
			break; // rotation restores height â€” stop
		} else {
			if (pBal == 2) {
				// left-heavy â†’ balanced, height unchanged â€” stop
				VadSetParentBalance(parent, ParentOff, gp, 0);
				break;
			}
			if (pBal == 0) {
				// balanced â†’ right-heavy, height grew â€” continue up
				VadSetParentBalance(parent, ParentOff, gp, 1);
				node = parent; parent = gp;
				continue;
			}
			// pBal == 1: right-heavy â†’ rotation required
			nBal = VadGetBalance(node, ParentOff);
			if (nBal == 1) {
				// RR â€” single left rotation
				VadRotateLeft(parent, LeftOff, RightOff, ParentOff, pRoot, 0, 0);
			} else {
				// RL â€” rotate node right then parent left
				m          = VadGetChild(node, LeftOff);
				mBal       = VadGetBalance(m, ParentOff);
				newNodeBal   = (mBal == 2) ? 1 : 0;
				newParentBal = (mBal == 1) ? 2 : 0;
				VadRotateRight(node,   LeftOff, RightOff, ParentOff, pRoot, newNodeBal,   0);
				VadRotateLeft (parent, LeftOff, RightOff, ParentOff, pRoot, newParentBal, 0);
			}
			break;
		}
	}
}

// =================================================================
// VAD AVL TREE â€” DELETE REBALANCING  (bottom-up from deletion point)
// Unlike insert a rotation may not shrink the subtree â†’ keep propagating.
// stop only when height is unchanged (0â†’1/0â†’2 balance change, or R0/L0 rotation).
// =================================================================

static VOID VadRebalanceDelete(PVOID start, BOOLEAN deletedFromLeft,
	DWORD LeftOff, DWORD RightOff, DWORD ParentOff, PVOID* pRoot) {
	PVOID   cur;
	BOOLEAN fromLeft;
	PVOID   curParent;
	BOOLEAN nextLeft;
	ULONG   bal;
	BOOLEAN cont;
	PVOID   r;
	ULONG   rBal;
	PVOID   l;
	ULONG   lBal;
	PVOID   m;
	ULONG   mBal;

	cur      = start;
	fromLeft = deletedFromLeft;

	while (cur != NULL) {
		curParent = VadGetParent(cur, ParentOff);
		nextLeft  = (curParent != NULL) && (VadGetChild(curParent, LeftOff) == cur);
		bal       = VadGetBalance(cur, ParentOff);

		if (fromLeft) {
			if (bal == 2) {
				// left-heavy â†’ balanced, height decreased â€” continue
				VadSetParentBalance(cur, ParentOff, curParent, 0);
				cont = TRUE;
			} else if (bal == 0) {
				// balanced â†’ right-heavy, height unchanged â€” stop
				VadSetParentBalance(cur, ParentOff, curParent, 1);
				cont = FALSE;
			} else {
				// bal==1: right subtree now taller by 2
				r    = VadGetChild(cur, RightOff);
				rBal = VadGetBalance(r, ParentOff);
				if (rBal == 0) {
					// R0: left rotation, height unchanged â€” stop
					VadRotateLeft(cur, LeftOff, RightOff, ParentOff, pRoot, 1, 2);
					cont = FALSE;
				} else if (rBal == 1) {
					// RR: left rotation, height decreased â€” continue
					VadRotateLeft(cur, LeftOff, RightOff, ParentOff, pRoot, 0, 0);
					cont = TRUE;
				} else {
					// RL: double rotation, height decreased â€” continue
					m    = VadGetChild(r, LeftOff);
					mBal = VadGetBalance(m, ParentOff);
					VadRotateRight(r,   LeftOff, RightOff, ParentOff, pRoot, (mBal == 2) ? 1 : 0, 0);
					VadRotateLeft (cur, LeftOff, RightOff, ParentOff, pRoot, (mBal == 1) ? 2 : 0, 0);
					cont = TRUE;
				}
			}
		} else {
			// mirror: deletion from the right subtree
			if (bal == 1) {
				VadSetParentBalance(cur, ParentOff, curParent, 0);
				cont = TRUE;
			} else if (bal == 0) {
				VadSetParentBalance(cur, ParentOff, curParent, 2);
				cont = FALSE;
			} else {
				// bal==2: left subtree now taller by 2
				l    = VadGetChild(cur, LeftOff);
				lBal = VadGetBalance(l, ParentOff);
				if (lBal == 0) {
					// L0: right rotation, height unchanged â€” stop
					VadRotateRight(cur, LeftOff, RightOff, ParentOff, pRoot, 2, 1);
					cont = FALSE;
				} else if (lBal == 2) {
					// LL: right rotation, height decreased â€” continue
					VadRotateRight(cur, LeftOff, RightOff, ParentOff, pRoot, 0, 0);
					cont = TRUE;
				} else {
					// LR: double rotation, height decreased â€” continue
					m    = VadGetChild(l, RightOff);
					mBal = VadGetBalance(m, ParentOff);
					VadRotateLeft (l,   LeftOff, RightOff, ParentOff, pRoot, (mBal == 1) ? 2 : 0, 0);
					VadRotateRight(cur, LeftOff, RightOff, ParentOff, pRoot, (mBal == 2) ? 1 : 0, 0);
					cont = TRUE;
				}
			}
		}

		if (!cont) break;
		cur      = curParent;
		fromLeft = nextLeft;
	}
}

// =================================================================
// VAD AVL TREE â€” STRUCTURAL SWAP  (X â†” in-order successor S)
// Precondition: X has two children; S is the leftmost node in X's right subtree.
// After the call X is in S's old position (X.left==NULL, X.right==S.oldRight).
// Returns the parent from which delete-rebalancing should start.
// *pFromLeft is set to indicate which side of that parent X now occupies.
// =================================================================

static PVOID VadSwapWithSuccessor(PVOID x, PVOID s,
	DWORD LeftOff, DWORD RightOff, DWORD ParentOff,
	PVOID* pRoot, PBOOLEAN pFromLeft) {
	PVOID   xParent;
	ULONG   xBalance;
	PVOID   xLeft;
	PVOID   xRight;
	PVOID   sParent;
	ULONG   sBalance;
	PVOID   sRight;
	BOOLEAN sDirect;

	xParent  = VadGetParent(x, ParentOff);
	xBalance = VadGetBalance(x, ParentOff);
	xLeft    = VadGetChild(x, LeftOff);
	xRight   = VadGetChild(x, RightOff);
	sParent  = VadGetParent(s, ParentOff);
	sBalance = VadGetBalance(s, ParentOff);
	sRight   = VadGetChild(s, RightOff);
	sDirect  = (xRight == s);

	// Put S in X's old position
	VadSetParentBalance(s, ParentOff, xParent, xBalance);
	if      (xParent == NULL)                    *pRoot = s;
	else if (VadGetChild(xParent, LeftOff) == x) VadSetChild(xParent, LeftOff,  s);
	else                                         VadSetChild(xParent, RightOff, s);

	VadSetChild(s, LeftOff, xLeft);
	if (xLeft) VadSetParentBalance(xLeft, ParentOff, s, VadGetBalance(xLeft, ParentOff));

	if (sDirect) {
		// S was X's direct right child â€” X goes as S's new right child
		VadSetChild(s, RightOff, x);
		VadSetParentBalance(x, ParentOff, s, sBalance);
		VadSetChild(x, LeftOff,  NULL);
		VadSetChild(x, RightOff, sRight);
		if (sRight) VadSetParentBalance(sRight, ParentOff, x, VadGetBalance(sRight, ParentOff));
		*pFromLeft = FALSE;
		return s;
	} else {
		// S was deeper â€” S adopts X's full right subtree, X takes sParent's left slot
		VadSetChild(s, RightOff, xRight);
		VadSetParentBalance(xRight, ParentOff, s, VadGetBalance(xRight, ParentOff));

		VadSetChild(sParent, LeftOff, x);
		VadSetParentBalance(x, ParentOff, sParent, sBalance);
		VadSetChild(x, LeftOff,  NULL);
		VadSetChild(x, RightOff, sRight);
		if (sRight) VadSetParentBalance(sRight, ParentOff, x, VadGetBalance(sRight, ParentOff));
		*pFromLeft = TRUE;
		return sParent;
	}
}

// =================================================================
// VAD AVL TREE â€” BST HELPERS
// =================================================================

// VadFindNode
// Checks VadHint first (O(1) fast path) before falling back to a full BST walk (O(log n)).
// hint  : value of EPROCESS.VadHint at call time — NULL is safe, check is skipped.
static PVOID VadFindNode(PVOID root, unsigned long long targetVpn,
	DWORD LeftOff, DWORD RightOff, DWORD StartingVpnOff, PVOID hint) {
	PVOID              cur;
	unsigned long long vpn;

	// Fast path: if the cached hint's StartingVpn matches we avoid the BST walk entirely
	if (hint != NULL && MmIsAddressValid(hint)) {
		if (VadGetStartingVpn(hint, StartingVpnOff) == targetVpn)
			return hint;
	}

	cur = root;
	while (cur != NULL && MmIsAddressValid(cur)) {
		vpn = VadGetStartingVpn(cur, StartingVpnOff);
		if      (targetVpn == vpn) return cur;
		else if (targetVpn  < vpn) cur = VadGetChild(cur, LeftOff);
		else                       cur = VadGetChild(cur, RightOff);
	}
	return NULL;
}

// VadConflictWalkUnlocked
// Lock-free BST overlap walk. Caller MUST hold AddressCreationLock (any mode).
BOOLEAN VadConflictWalkUnlocked(PVOID root, PSYM_INFO Syms,
	unsigned long long startVpn, unsigned long long endVpn) {
#define CONFLICT_STACK_DEPTH 64
	PVOID stack[CONFLICT_STACK_DEPTH];
	int   top = 0;
	PVOID cur = root;
	unsigned long long nodeStart, nodeEnd;
	ULONG endLow;
	UCHAR endHigh;

	while ((cur != NULL && MmIsAddressValid(cur)) || top > 0) {
		while (cur != NULL && MmIsAddressValid(cur)) {
			nodeStart = VadGetStartingVpn(cur, Syms->StartingVpnOffset);
			if (nodeStart > endVpn) break; // right subtree also out of range
			if (top < CONFLICT_STACK_DEPTH) stack[top++] = cur;
			cur = VadGetChild(cur, Syms->Left);
		}
		if (top == 0) break;
		cur = stack[--top];

		nodeStart = VadGetStartingVpn(cur, Syms->StartingVpnOffset);
		endLow    = *(ULONG*)((ULONG_PTR)cur + Syms->EndingVpnOffset);
		endHigh   = *(UCHAR*)((ULONG_PTR)cur + Syms->EndingVpnOffset + 5);
		nodeEnd   = (unsigned long long)endLow | ((unsigned long long)endHigh << 32);

		if (nodeStart <= endVpn && startVpn <= nodeEnd) {
			DbgPrint("[-] VadConflictWalk: overlap node 0x%p (VPN 0x%llx-0x%llx) vs (0x%llx-0x%llx)\n",
				cur, nodeStart, nodeEnd, startVpn, endVpn);
			return TRUE;
		}
		cur = VadGetChild(cur, Syms->Right);
	}
#undef CONFLICT_STACK_DEPTH
	return FALSE;
}

// Links NewNode into the BST (no rebalance). NewNode's StartingVpn must
// already be encoded. Returns FALSE on duplicate VPN.
static BOOLEAN VadBstLink(PVOID root, PVOID newNode,
	DWORD LeftOff, DWORD RightOff,
	DWORD ParentOff, DWORD StartingVpnOff, PVOID* pRoot) {
	unsigned long long newVpn;
	unsigned long long curVpn;
	PVOID              cur;
	PVOID              parent;
	BOOLEAN            isLeft;

	VadSetChild(newNode, LeftOff,  NULL);
	VadSetChild(newNode, RightOff, NULL);

	if (root == NULL) {
		VadSetParentBalance(newNode, ParentOff, NULL, 0);
		*pRoot = newNode;
		return TRUE;
	}

	newVpn = VadGetStartingVpn(newNode, StartingVpnOff);
	cur    = root;
	parent = NULL;
	isLeft = FALSE;

	while (cur != NULL && MmIsAddressValid(cur)) {
		curVpn = VadGetStartingVpn(cur, StartingVpnOff);
		if      (newVpn < curVpn) { parent = cur; isLeft = TRUE;  cur = VadGetChild(cur, LeftOff);  }
		else if (newVpn > curVpn) { parent = cur; isLeft = FALSE; cur = VadGetChild(cur, RightOff); }
		else                      return FALSE; // duplicate VPN
	}

	VadSetParentBalance(newNode, ParentOff, parent, 0);
	if (isLeft) VadSetChild(parent, LeftOff,  newNode);
	else        VadSetChild(parent, RightOff, newNode);
	return TRUE;
}

// =================================================================
// VAD AVL TREE â€” PUBLIC API
// =================================================================

// VadTreeInsert
// NewNode must be a fully initialised MMVAD-compatible allocation with its
// StartingVpn already encoded at Syms->StartingVpnOffset.
// Does NOT allocate the node. Caller holds no spinlock; IRQL <= APC_LEVEL.
NTSTATUS VadTreeInsert(PEPROCESS Process, PSYM_INFO Syms, PVOID NewNode) {
	PVOID*        pRoot;
	PEX_PUSH_LOCK pLock;
	BOOLEAN       linked;

	if (!Process || !Syms || !NewNode) return STATUS_INVALID_PARAMETER;

	pRoot  = (PVOID*)((ULONG_PTR)Process + Syms->VADRoot);
	pLock  = (PEX_PUSH_LOCK)((ULONG_PTR)Process + Syms->AddressCreationLock);

	KeEnterCriticalRegion();
	ExAcquirePushLockExclusive(pLock);

	linked = VadBstLink(*pRoot, NewNode,
		Syms->Left, Syms->Right,
		Syms->ParentValue, Syms->StartingVpnOffset,
		pRoot);
	if (linked) {
		VadRebalanceInsert(NewNode, Syms->Left, Syms->Right, Syms->ParentValue, pRoot);
		// VadHint: point at the freshly inserted node for O(1) next lookup
		*(PVOID*)((ULONG_PTR)Process + Syms->VadHint) = NewNode;
		// VadFreeHint: insertion consumed space — null it so the kernel recalculates
		*(PVOID*)((ULONG_PTR)Process + Syms->VadFreeHint) = NULL;
	}

	ExReleasePushLockExclusive(pLock);
	KeLeaveCriticalRegion();

	if (!linked) {
		DbgPrint("[-] VadTreeInsert: duplicate StartingVpn, node not inserted\n");
		return STATUS_DUPLICATE_NAME;
	}
	DbgPrint("[+] VadTreeInsert: node 0x%p inserted\n", NewNode);
	return STATUS_SUCCESS;
}

// VadTreeRemove
// Finds the MMVAD node whose StartingVpn == targetVpn, unlinks it and rebalances.
// Does NOT free the allocation â€” caller owns it.
// On success *pRemovedNode receives the unlinked node pointer (may be NULL if unwanted).
NTSTATUS VadTreeRemove(PEPROCESS Process, PSYM_INFO Syms, unsigned long long targetVpn,
	PVOID* pRemovedNode) {
	PVOID*        pRoot;
	PEX_PUSH_LOCK pLock;
	PVOID         x;
	PVOID         xLeft;
	PVOID         xRight;
	PVOID         rebalanceFrom;
	BOOLEAN       fromLeft;
	PVOID         s;
	PVOID         sl;
	PVOID         child;
	PVOID         xParent;
	PVOID         hint;        // snapshot of VadHint before we touch the tree

	if (!Process || !Syms) return STATUS_INVALID_PARAMETER;
	if (pRemovedNode) *pRemovedNode = NULL;

	pRoot = (PVOID*)((ULONG_PTR)Process + Syms->VADRoot);
	pLock = (PEX_PUSH_LOCK)((ULONG_PTR)Process + Syms->AddressCreationLock);

	KeEnterCriticalRegion();
	ExAcquirePushLockExclusive(pLock);

	// Read VadHint inside the lock for a consistent view
	hint = *(PVOID*)((ULONG_PTR)Process + Syms->VadHint);

	x = VadFindNode(*pRoot, targetVpn, Syms->Left, Syms->Right, Syms->StartingVpnOffset, hint);
	if (!x) {
		ExReleasePushLockExclusive(pLock);
		KeLeaveCriticalRegion();
		return STATUS_NOT_FOUND;
	}

	xLeft  = VadGetChild(x, Syms->Left);
	xRight = VadGetChild(x, Syms->Right);

	if (xLeft != NULL && xRight != NULL) {
		// Two children: find in-order successor (leftmost node in right subtree)
		s = xRight;
		while (MmIsAddressValid(s)) {
			sl = VadGetChild(s, Syms->Left);
			if (sl == NULL || !MmIsAddressValid(sl)) break;
			s = sl;
		}
		// Structurally swap X with S; X lands in S's old position (at most one child)
		rebalanceFrom = VadSwapWithSuccessor(x, s,
			Syms->Left, Syms->Right, Syms->ParentValue,
			pRoot, &fromLeft);
		xLeft  = VadGetChild(x, Syms->Left);  // always NULL after swap
		xRight = VadGetChild(x, Syms->Right);
	} else {
		// Zero or one child â€” splice directly
		rebalanceFrom = VadGetParent(x, Syms->ParentValue);
		fromLeft      = (rebalanceFrom != NULL) &&
			(VadGetChild(rebalanceFrom, Syms->Left) == x);
	}

	// Splice X out: replace with its sole remaining child (may be NULL)
	child   = (xRight != NULL) ? xRight : xLeft;
	xParent = VadGetParent(x, Syms->ParentValue);

	if      (xParent == NULL)                           *pRoot = child;
	else if (VadGetChild(xParent, Syms->Left) == x)     VadSetChild(xParent, Syms->Left,  child);
	else                                                VadSetChild(xParent, Syms->Right, child);

	if (child)
		VadSetParentBalance(child, Syms->ParentValue, xParent,
			VadGetBalance(child, Syms->ParentValue));

	if (rebalanceFrom)
		VadRebalanceDelete(rebalanceFrom, fromLeft,
			Syms->Left, Syms->Right, Syms->ParentValue, pRoot);

	// Maintain VadHint: if it was pointing at the removed node, redirect to its
	// structural replacement. child (took X's slot) is preferred; fall back to xParent.
	if (hint == x)
		*(PVOID*)((ULONG_PTR)Process + Syms->VadHint) = (child != NULL) ? child : xParent;

	// VadFreeHint: removal opens a free region — null it so the kernel recomputes on
	// the next VirtualAlloc rather than chasing a stale pointer into freed memory.
	*(PVOID*)((ULONG_PTR)Process + Syms->VadFreeHint) = NULL;

	ExReleasePushLockExclusive(pLock);
	KeLeaveCriticalRegion();

	if (pRemovedNode) *pRemovedNode = x;
	DbgPrint("[+] VadTreeRemove: node 0x%p (VPN 0x%llx) unlinked\n", x, targetVpn);
	return STATUS_SUCCESS;
}

// =================================================================
// VAD AVL TREE — PUBLIC BST CONFLICT CHECK
// =================================================================

// VadCheckConflict
// Public entry point: acquires AddressCreationLock shared, then delegates
// to VadConflictWalkUnlocked. Use this when the caller holds NO lock.
// If you already hold AddressCreationLock exclusively, call
// VadConflictWalkUnlocked directly to avoid a deadlock.
BOOLEAN VadCheckConflict(PEPROCESS Process, PSYM_INFO Syms,
	unsigned long long startVpn, unsigned long long endVpn) {
	PVOID*        pRoot;
	PEX_PUSH_LOCK pLock;
	BOOLEAN       found;

	if (!Process || !Syms) return FALSE;

	pRoot = (PVOID*)((ULONG_PTR)Process + Syms->VADRoot);
	pLock = (PEX_PUSH_LOCK)((ULONG_PTR)Process + Syms->AddressCreationLock);

	KeEnterCriticalRegion();
	ExAcquirePushLockShared(pLock);
	found = VadConflictWalkUnlocked(
		(pRoot && MmIsAddressValid(pRoot)) ? *pRoot : NULL,
		Syms, startVpn, endVpn);
	ExReleasePushLockShared(pLock);
	KeLeaveCriticalRegion();
	return found;
}

// =================================================================
// VAD AVL TREE — PUBLIC BST SEARCH
// =================================================================

// VadFindNodeByVpn
// Locks AddressCreationLock shared, searches the BST for the node
// whose StartingVpn equals targetVpn, and returns it (or NULL).
// IRQL <= APC_LEVEL required.
PVOID VadFindNodeByVpn(PEPROCESS Process, PSYM_INFO Syms, unsigned long long targetVpn) {
	PVOID*        pRoot;
	PEX_PUSH_LOCK pLock;
	PVOID         hint;
	PVOID         result;

	if (!Process || !Syms) return NULL;

	pRoot = (PVOID*)((ULONG_PTR)Process + Syms->VADRoot);
	pLock = (PEX_PUSH_LOCK)((ULONG_PTR)Process + Syms->AddressCreationLock);

	KeEnterCriticalRegion();
	ExAcquirePushLockShared(pLock);

	hint   = *(PVOID*)((ULONG_PTR)Process + Syms->VadHint);
	result = VadFindNode(*pRoot, targetVpn, Syms->Left, Syms->Right, Syms->StartingVpnOffset, hint);

	ExReleasePushLockShared(pLock);
	KeLeaveCriticalRegion();
	return result;
}

// =================================================================
// VAD AVL TREE — OPTIONAL POOL HELPERS
// These are convenience wrappers; callers that manage their own
// allocations (e.g. re-using mapped memory) can ignore them entirely.
//
// A VAD_ALLOC_HEADER (8 bytes) is prepended to every VadAllocateNode
// allocation. VadFreeNode checks the magic field to distinguish our
// nodes from kernel-allocated MMVAD nodes — if the magic is absent the
// node is NOT freed (it belongs to Windows and must not be touched).
//
// Pool tag: 'MADV'
// =================================================================

#define VAD_NODE_POOL_TAG  'MADV'
#define VAD_ALLOC_MAGIC    0x4D564441U  // 'MVDA'

typedef struct _VAD_ALLOC_HEADER {
	ULONG  Magic;   // VAD_ALLOC_MAGIC when allocated by VadAllocateNode
	ULONG  Size32;  // original requested size (debug aid)
} VAD_ALLOC_HEADER;  // exactly 8 bytes — MMVAD stays 8-byte aligned

// VadAllocateNode
// Allocates sizeof(VAD_ALLOC_HEADER) + size bytes from NonPagedPool,
// zero-fills the payload, stamps the header, and returns a pointer to the
// payload (i.e. the start of the caller's MMVAD-compatible struct).
// Pass sizeof(your_MMVAD_struct) as size.
NTSTATUS VadAllocateNode(SIZE_T size, PVOID* pNode) {
	VAD_ALLOC_HEADER* hdr;

	if (!pNode) return STATUS_INVALID_PARAMETER;
	*pNode = NULL;

	hdr = (VAD_ALLOC_HEADER*)ExAllocatePool2(
		POOL_FLAG_NON_PAGED, sizeof(VAD_ALLOC_HEADER) + size, VAD_NODE_POOL_TAG);
	if (!hdr) {
		DbgPrint("[-] VadAllocateNode: ExAllocatePool2 failed (size=%zu)\n", size);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	// ExAllocatePool2 always zeroes — just stamp the header
	hdr->Magic  = VAD_ALLOC_MAGIC;
	hdr->Size32 = (ULONG)size;
	*pNode = (PVOID)(hdr + 1);  // caller receives pointer past the header
	return STATUS_SUCCESS;
}

// VadFreeNode
// Safe to call on ANY node pointer returned by VadTreeRemove:
//
//   OUR allocation  (VadAllocateNode) — the hidden VAD_ALLOC_HEADER sits
//     8 bytes behind the pointer. Magic is verified, header is poisoned,
//     and ExFreePoolWithTag frees the full (header + payload) block with
//     the correct 'MADV' tag.
//
//   KERNEL allocation (Windows MMVAD, tag 'VadS' / 'Vad ' / etc.) — the
//     magic check fails. ExFreePool is used: it accepts any valid pool
//     pointer and frees it without tag validation, so no BAD_POOL_CALLER.
//
// Safe to call with NULL.
VOID VadFreeNode(PVOID node) {
	VAD_ALLOC_HEADER* hdr;

	if (!node) return;
	hdr = (VAD_ALLOC_HEADER*)node - 1;

	if (MmIsAddressValid(hdr) && hdr->Magic == VAD_ALLOC_MAGIC) {
		hdr->Magic = 0;  // poison — prevents double-free reuse
		ExFreePoolWithTag(hdr, VAD_NODE_POOL_TAG);
		DbgPrint("[+] VadFreeNode: freed VadAllocateNode block at 0x%p\n", node);
	} else {
		// Kernel-allocated MMVAD — free without tag check
		DbgPrint("[*] VadFreeNode: freeing kernel node 0x%p via ExFreePool\n", node);
		ExFreePool(node);
	}
}


// Inline bit-field extractor — identical logic to usermode ExtractBits.
#define VAD_EXTRACT_BITS(raw, pos, len) (((len) && (len) < 32) ? (((raw) >> (pos)) & ((1u << (len)) - 1u)) : 0u)

BOOL InsertVADNode(int Level,
	PVOID VADNode,
	unsigned long long StartingVpn,
	unsigned long long EndingVpn,
	UNICODE_STRING* FileName,
	ULONG VadFlagsRaw,
	ULONG ControlAreaFlags,
	ULONG64 ControlAreaPtr,
	ULONG MappedViews,
	ULONG SectionReferences,
	BOOLEAN IsVadShort) {

	if (gViewSize / sizeof(VAD_NODE) <= gSecVADIndex) {
		DbgPrint("[-] VAD node index out of bounds\n");
		return FALSE;
	}
	if (gFileNameViewSize / sizeof(VAD_NODE_FILE) <= gCurrFileNameOffset) {
		DbgPrint("[-] FileName node index out of bounds\n");
		return FALSE;
	}

	PVAD_NODE CurrVADNode = (PVAD_NODE)gSection;
	PVAD_NODE_FILE FileNameBuffer = (PVAD_NODE_FILE)gFileNameSection;

	CurrVADNode[gSecVADIndex].Level = Level;
	CurrVADNode[gSecVADIndex].VADNode = VADNode;
	CurrVADNode[gSecVADIndex].StartingVpn = StartingVpn;
	CurrVADNode[gSecVADIndex].EndingVpn = EndingVpn;
	CurrVADNode[gSecVADIndex].FileOffset = 0;
	CurrVADNode[gSecVADIndex].VadFlagsRaw = VadFlagsRaw;
	CurrVADNode[gSecVADIndex].ControlAreaFlags = ControlAreaFlags;
	CurrVADNode[gSecVADIndex].ControlAreaPtr = ControlAreaPtr;
	CurrVADNode[gSecVADIndex].MappedViews = MappedViews;
	CurrVADNode[gSecVADIndex].SectionReferences = SectionReferences;
	CurrVADNode[gSecVADIndex].SharedProcessCount = 0; // filled post-walk
	CurrVADNode[gSecVADIndex].IsVadShort = IsVadShort;
	// Protection is always at the same bit position — _MMVAD_SHORT.u is embedded at
	// offset 0 of _MMVAD_SHORT, which is also Core.u in full _MMVAD
	CurrVADNode[gSecVADIndex].Protection =
		VAD_EXTRACT_BITS(VadFlagsRaw, gSymInfo.ProtectionBitPos, gSymInfo.ProtectionBitLen);
	if (FileName != NULL && FileName->Length > 0 && FileName->Length < gViewSize) {
		ANSI_STRING test;
		if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&test, FileName, TRUE))) {
			size_t size = min(test.Length, sizeof(VAD_NODE_FILE) - 128 - 1);
			memcpy(FileNameBuffer[gCurrFileNameOffset].FileName, test.Buffer, size);
			FileNameBuffer[gCurrFileNameOffset].FileName[min(size, MAX_FILENAME_SIZE - 1)] = '\0';
			RtlFreeAnsiString(&test);

			// ObQueryNameString on the _FILE_OBJECT to get the full NT device path.
			// FileName points into _FILE_OBJECT.FileName (a UNICODE_STRING member),
			// so _FILE_OBJECT* = (ULONG_PTR)FileName - gSymInfo.FILEOBJECTFileName.
			FileNameBuffer[gCurrFileNameOffset].DevPath[0] = '\0';
			if (gSymInfo.FILEOBJECTFileName) {
				typedef NTSTATUS (*PFN_QNS)(PVOID, POBJECT_NAME_INFORMATION, ULONG, PULONG);
				static PFN_QNS fnQNS = NULL;
				if (!fnQNS) {
					UNICODE_STRING us;
					RtlInitUnicodeString(&us, L"ObQueryNameString");
					fnQNS = (PFN_QNS)MmGetSystemRoutineAddress(&us);
				}
				if (fnQNS) {
					PVOID fileObj = (PVOID)((ULONG_PTR)FileName - gSymInfo.FILEOBJECTFileName);
					if (MmIsAddressValid(fileObj)) {
						UCHAR nameBuf[512];
						ULONG returned = 0;
						POBJECT_NAME_INFORMATION oni = (POBJECT_NAME_INFORMATION)nameBuf;
						if (NT_SUCCESS(fnQNS(fileObj, oni, sizeof(nameBuf), &returned)) &&
							oni->Name.Length > 0 && MmIsAddressValid(oni->Name.Buffer)) {
							ULONG ci;
							ULONG nc = oni->Name.Length / sizeof(WCHAR);
							if (nc > 127) nc = 127;
							for (ci = 0; ci < nc; ci++)
								FileNameBuffer[gCurrFileNameOffset].DevPath[ci] =
									(oni->Name.Buffer[ci] < 128) ? (CHAR)oni->Name.Buffer[ci] : '?';
							FileNameBuffer[gCurrFileNameOffset].DevPath[nc] = '\0';
						}
					}
				}
			}

			CurrVADNode[gSecVADIndex].FileOffset = gCurrFileNameOffset;
			gCurrFileNameOffset++;
		}
		else {
			DbgPrint("[-] Failed to convert FileName to ANSI\n");
		}
	}

	gSecVADIndex++;
	return TRUE;
}
UNICODE_STRING* GetFileObjectFromVADLeaf(unsigned long long Leaf, DWORD MMVADSubsection, DWORD MMVADControlArea, DWORD MMVADCAFilePointer, DWORD MMCAFlags, DWORD FILEOBJECTFileName, PULONG pControlAreaFlags, PULONG pMappedViews, PULONG pSectionReferences, PULONG64 pControlAreaPtr) {
	if (Leaf == 0)
		return NULL;

	unsigned long long SubsectionPtr = *(PVOID*)(Leaf + MMVADSubsection);
	if (!MmIsAddressValid((PVOID)SubsectionPtr))
		return NULL;

	unsigned long long ControlArea = *(PVOID*)(SubsectionPtr);
	if (!MmIsAddressValid((PVOID)ControlArea))
		return NULL;

	// Read MMSECTION_FLAGS, NumberOfMappedViews, NumberOfUserReferences from _CONTROL_AREA
	if (pControlAreaPtr)
		*pControlAreaPtr = ControlArea;
	if (pControlAreaFlags && MmIsAddressValid((PVOID)(ControlArea + MMCAFlags)))
		*pControlAreaFlags = *(ULONG*)(ControlArea + MMCAFlags);
	if (pMappedViews && gSymInfo.MMCAMappedViews && MmIsAddressValid((PVOID)(ControlArea + gSymInfo.MMCAMappedViews)))
		*pMappedViews = *(ULONG*)(ControlArea + gSymInfo.MMCAMappedViews);
	if (pSectionReferences && gSymInfo.MMCASectionReferences && MmIsAddressValid((PVOID)(ControlArea + gSymInfo.MMCASectionReferences)))
		*pSectionReferences = *(ULONG*)(ControlArea + gSymInfo.MMCASectionReferences);

	unsigned long long FilePointer = (PVOID*)(ControlArea + MMVADCAFilePointer);
	if (!MmIsAddressValid((PVOID)FilePointer))
		return NULL;

	unsigned long long FileObject = *(PVOID*)FilePointer;
	if (!MmIsAddressValid((PVOID)FileObject))
		return NULL;

	FileObject = FileObject - (FileObject & 0xF);
	if (!MmIsAddressValid((PVOID)(FileObject + FILEOBJECTFileName)))
		return NULL;

	UNICODE_STRING* FileName = (UNICODE_STRING*)(FileObject + FILEOBJECTFileName);
	if (!MmIsAddressValid(FileName->Buffer))
		return NULL;

	return FileName;
}
VOID WalkVADIterative(PVOID Root, unsigned long StartingVpnOffset, DWORD EndingVpnOffset,
	DWORD Left, DWORD Right,
	PULONG TotalVADs, PULONG TotalLevels, PULONG MaxDepth,
	DWORD MMVADSubsection, DWORD MMVADControlArea, DWORD MMVADCAFilePointer, DWORD MMCAFlags, DWORD FILEOBJECTFileName,
	unsigned long long targetAdr) {

#define VAD_STACK_SIZE 512
	// Each stack slot holds the node pointer and its level
	struct { PVOID Node; int Level; } stack[VAD_STACK_SIZE];
	int top = 0;

	if (Root == NULL || !MmIsAddressValid(Root))
		return;

	stack[top].Node  = Root;
	stack[top].Level = 1;
	top++;

	while (top > 0) {
		top--;
		PVOID VADNode = stack[top].Node;
		int   Level   = stack[top].Level;

		if (!MmIsAddressValid(VADNode))
			continue;

		// Update statistics
		(*TotalVADs)++;
		(*TotalLevels) += Level;
		if (Level > (int)*MaxDepth)
			*MaxDepth = (ULONG)Level;

		// Decode StartingVpn / EndingVpn (same logic as the old recursive walker)
		unsigned long long Vpn         = *(unsigned long long*)((unsigned long long)VADNode + StartingVpnOffset);
		unsigned long long VpnStart    = Vpn & 0xFFFFFFFF;
		unsigned long long VpnEnd      = (Vpn >> 32) & 0xFFFFFFFF;
		unsigned long long VpnHigh     = *(unsigned long long*)((unsigned long long)VADNode + 0x20);
		unsigned long long VpnHighPart0 = (VpnHigh & 0xFF) << 32;
		unsigned long long VpnHighPart1 = ((VpnHigh >> 8) & 0xFF) << 32;
		unsigned long long StartingVpn = VpnStart | VpnHighPart0;
		unsigned long long EndingVpn   = VpnEnd   | VpnHighPart1;

		UNICODE_STRING* FileName = NULL;
		ULONG caFlags = 0, mappedViews = 0, sectionRefs = 0;
		ULONG64 caPtr = 0;

		unsigned long long SubsectionProbe = *(ULONG_PTR*)((ULONG_PTR)VADNode + MMVADSubsection);
		BOOLEAN isShort = (SubsectionProbe == 0 || !MmIsAddressValid((PVOID)SubsectionProbe));

		ULONG VadFlagsRaw = *(ULONG*)((ULONG_PTR)VADNode + gSymInfo.MMVADFlagsOffset);
		ULONG privateMemory = VAD_EXTRACT_BITS(VadFlagsRaw, gSymInfo.PrivateMemoryBitPos, 1);

		if (!privateMemory && !isShort) {
			FileName = GetFileObjectFromVADLeaf((unsigned long long)VADNode,
				MMVADSubsection, MMVADControlArea, MMVADCAFilePointer, MMCAFlags, FILEOBJECTFileName,
				&caFlags, &mappedViews, &sectionRefs, &caPtr);
		}

		InsertVADNode(Level, VADNode, StartingVpn, EndingVpn, FileName, VadFlagsRaw, caFlags, caPtr, mappedViews, sectionRefs, isShort);

		// Push children â€” bounds-check to avoid stack overflow
		PVOID RightChild = *(PVOID*)((ULONG_PTR)VADNode + Right);
		PVOID LeftChild  = *(PVOID*)((ULONG_PTR)VADNode + Left);

		if (RightChild && MmIsAddressValid(RightChild) && top < VAD_STACK_SIZE - 1) {
			stack[top].Node  = RightChild;
			stack[top].Level = Level + 1;
			top++;
		}
		if (LeftChild && MmIsAddressValid(LeftChild) && top < VAD_STACK_SIZE - 1) {
			stack[top].Node  = LeftChild;
			stack[top].Level = Level + 1;
			top++;
		}
	}
#undef VAD_STACK_SIZE
}
// Returns TRUE if any node in the VAD tree of EProcess has a Subsection->ControlArea
// matching targetCA. Used to detect cross-process section sharing.
// =================================================================
// AllocateSubsectionChain
//
// Allocates and initialises a minimal _CONTROL_AREA + embedded
// _SUBSECTION + _SEGMENT triple for non-private VAD types, mirroring
// exactly what MiCreatePagingFileMap does.
//
// Layout derived from MiCreatePagingFileMap disassembly:
//
//  Pool alloc 1 — _CONTROL_AREA + inline _SUBSECTION
//    size  = 0x80 (_CONTROL_AREA) + numSubs * 0x58 (_SUBSECTION)
//    tag   = 'MmCa' (0x61436D4D)
//    type  = NonPagedPoolNx (0x40)
//
//  Pool alloc 2 — _SEGMENT
//    size  = 0x50
//    tag   = 'MmSe' (0x65536D4D)  [observed at MiCreatePagingFileMap+0x37f]
//    type  = PagedPool (0x100)
//
// Fields initialised (offsets from MiCreatePagingFileMap):
//   CA+0x00  Segment            → Segment ptr
//   CA+0x08  Flink (self)
//   CA+0x10  Blink (self)
//   CA+0x18  NumberOfSectionReferences = 1
//   CA+0x28  NumberOfMappedViews       = 1
//   CA+0x30  NumberOfUserReferences    = 1
//   CA+0x38  LongFlags (MMSECTION_FLAGS) = Commit | File | Pagefile-backed
//   CA+0x48  ControlAreaLock (EX_PUSH_LOCK) = 0
//   CA+0x60  NumberOfSubsections       = numSubs
//   CA+0x70  LockedPages               = 1
//   CA+0x80  first embedded _SUBSECTION
//
//   Sub+0x00 ControlArea → CA
//   Sub+0x2C PtesInSubsection = pages in this sub
//   Sub+0x28 StartingSector   = starting page offset
//   Sub+0x50 SubsectionBase (LIST_ENTRY, self-link)
//
//   Seg+0x00 ControlArea → CA
//   Seg+0x08 TotalNumberOfPtes = totalPages
//   Seg+0x18 SizeOfSegment     = totalPages << 12
//
// On success: *ppControlArea and *ppSegment point to the allocations.
// Caller is responsible for freeing both on error or on VAD removal.
// =================================================================
NTSTATUS AllocateSubsectionChain(
	unsigned long long totalPages,
	ULONG vadType,           // MI_VAD_TYPE — drives MMSECTION_FLAGS selection
	ULONG mmProtection,      // 5-bit MMVAD protection value (same as stored in MMVAD_FLAGS)
	PVOID*  ppControlArea,
	PVOID*  ppSegment,
	PVOID*  ppProtoPTEs)     // out: prototype PTE array (numPages * 8 bytes)
{
	if (!ppControlArea || !ppSegment || !ppProtoPTEs || totalPages == 0)
		return STATUS_INVALID_PARAMETER;

	*ppControlArea = NULL;
	*ppSegment     = NULL;
	*ppProtoPTEs   = NULL;

	// ── _SEGMENT (0x50 bytes, PagedPool, tag 'MmSe') ─────────────────
	// MiCreatePagingFileMap+0x37f:
	//   mov edx,50h / mov ecx,100h / mov r8d,'MmSe' / call MiAllocatePool
	PVOID pSeg = ExAllocatePool2(POOL_FLAG_PAGED, 0x50, 'eSmM');
	if (!pSeg)
		return STATUS_INSUFFICIENT_RESOURCES;
	RtlZeroMemory(pSeg, 0x50);

	// ── _CONTROL_AREA + embedded _SUBSECTION[1] ───────────────────────
	// MiCreatePagingFileMap+0x353:
	//   imul rdx,r15,58h  (numSubs * 0x58)
	//   sub  rdx,-0x80    (add 0x80 for CONTROL_AREA header)
	//   mov  ecx,40h / mov r8d,'MmCa' / call MiAllocatePool
	SIZE_T caSize = 0x80 + 1 * 0x58;   // exactly 1 subsection for ghost VAD
	PVOID pCA = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, caSize, 'aCmM');
	if (!pCA) {
		ExFreePool(pSeg);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(pCA, caSize);

	// ── Initialise _CONTROL_AREA ──────────────────────────────────────
	// Segment ptr  [+0x00]
	*(PVOID*)((ULONG_PTR)pCA + 0x00) = pSeg;

	// DereferenceList self-link [+0x08 / +0x10]
	// MiCreatePagingFileMap+0x3a5: lea rax,[rbx+8] / mov [rax+8],rax / mov [rax],rax
	PVOID pLink = (PVOID)((ULONG_PTR)pCA + 0x08);
	*(PVOID*)((ULONG_PTR)pCA + 0x08) = pLink;
	*(PVOID*)((ULONG_PTR)pCA + 0x10) = pLink;

	// NumberOfSectionReferences [+0x18] = 1
	*(ULONG*)((ULONG_PTR)pCA + 0x18) = 1;

	// NumberOfMappedViews [+0x28] = 1
	*(ULONG*)((ULONG_PTR)pCA + 0x28) = 1;

	// NumberOfUserReferences [+0x30] = 1
	// MiCreatePagingFileMap+0x3ca: mov qword ptr [rbx+30h],rax (rax=1)
	*(ULONG*)((ULONG_PTR)pCA + 0x30) = 1;

	// MMSECTION_FLAGS [+0x38]
	// DO NOT set the Commit flag (bit 13 = 0x2000).
	// When Commit is set, MiDeleteVad calls MiRemoveSharedCommitNode on process
	// exit to deregister from the global pagefile commit tracking list.  Since
	// we never called MiUpdateControlAreaCommitCount the SharedCommitNode pointer
	// at Seg+0x30 is zero → MiRemoveSharedCommitNode dereferences NULL → bugcheck.
	// MEM_COMMIT is reported by MiQueryAddressState from the prototype PTE protection
	// bits (non-zero = committed), not from this flag, so omitting it is safe.
	ULONG caFlags;
	switch (vadType) {
	case 2:  caFlags = 0x0020; break;  // VadImageMap:            Image (bit 5)
	case 1:  caFlags = 0x0400; break;  // VadDevicePhysicalMemory: PhysicalMemory (bit 10)
	default: caFlags = 0x0000; break;  // VadLargePageSection / VadRotatePhysical / others
	}
	*(ULONG*)((ULONG_PTR)pCA + 0x38) = caFlags;

	// NumberOfSubsections [+0x60] = 1
	*(ULONG*)((ULONG_PTR)pCA + 0x60) = 1;

	// LockedPages [+0x70] = 1
	// MiCreatePagingFileMap+0x3ca: mov qword ptr [rbx+70h],rax (rax=1)
	*(ULONG64*)((ULONG_PTR)pCA + 0x70) = 1;

	// ── Initialise embedded _SUBSECTION [CA+0x80] ────────────────────
	PVOID pSub = (PVOID)((ULONG_PTR)pCA + 0x80);

	// ControlArea [Sub+0x00] → CA
	*(PVOID*)((ULONG_PTR)pSub + 0x00) = pCA;

	// SubsectionBase [Sub+0x08] — prototype PTE array.
	// Each PTE must be a fully-formatted MMPTE_SOFTWARE demand-zero entry.
	// From MiInitializePrototypePtes disasm:
	//   - If Segment->FirstMappedVa (CA->Segment[+0x40]) is NULL →
	//       reads Sub+0x20 bits[5:1] as protectionIndex, calls MiMakeDemandZeroPte(protectionIndex)
	//   - MiMakeDemandZeroPte returns the 64-bit PTE value to stamp into every slot
	// The MMVAD protection value is NOT the same as the MM protection index:
	//   MMVAD 0x01=RO→idx 1, 0x02=RX→idx 3, 0x03=RW/C→idx 2 (copy-on-write),
	//   0x04=RW→idx 2, 0x05=RWC→idx 2, 0x06=RWX/C→idx 4, 0x07=RWX→idx 4
	static const ULONG mmVadToProtIndex[8] = { 0, 1, 3, 2, 2, 2, 4, 4 };
	ULONG protIdx = (mmProtection < 8) ? mmVadToProtIndex[mmProtection] : 4;

	SIZE_T ptesSize = totalPages * 8;
	PVOID pPTEs = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, ptesSize, 'ePmM');
	if (!pPTEs) {
		ExFreePool(pSeg);
		ExFreePool(pCA);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Set SubsectionFlags [Sub+0x20] bits[5:1] = protIdx so MiInitializePrototypePtes
	// reads the correct protection when it calls MiMakeDemandZeroPte internally.
	USHORT subFlags = *(USHORT*)((ULONG_PTR)pSub + 0x20);
	subFlags &= ~0x003Eu;
	subFlags |= (USHORT)((protIdx & 0x1Fu) << 1);
	*(USHORT*)((ULONG_PTR)pSub + 0x20) = subFlags;

	// Wire the array before calling MiInitializePrototypePtes.
	*(PVOID*)((ULONG_PTR)pSub + 0x08) = pPTEs;

	// Use MiMakeDemandZeroPte to get the canonical PTE value and fill the array.
	// This is exactly what MiInitializePrototypePtes does at +0xa0 when Segment+0x40 == NULL.
	ULONG64 pteVal = 0;
	if (gSymInfo.MiMakeDemandZeroPte && gInit.NtBaseOffset) {
		typedef ULONG64(*PFN_DZ)(ULONG protectionIndex);
		PFN_DZ fnDZ = (PFN_DZ)(gInit.NtBaseOffset + gSymInfo.MiMakeDemandZeroPte);
		__try {
			pteVal = fnDZ(protIdx);
			DbgPrint("[+] AllocateSubsectionChain: MiMakeDemandZeroPte(idx=%lu) = 0x%016llx\n", protIdx, pteVal);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrint("[-] AllocateSubsectionChain: MiMakeDemandZeroPte raised %08X\n", GetExceptionCode());
			pteVal = (ULONG64)protIdx << 5;  // emergency fallback
		}
	} else {
		DbgPrint("[-] AllocateSubsectionChain: MiMakeDemandZeroPte not resolved — using raw shift\n");
		pteVal = (ULONG64)protIdx << 5;
	}

	ULONG64* pteArray = (ULONG64*)pPTEs;
	for (unsigned long long i = 0; i < totalPages; i++)
		pteArray[i] = pteVal;

	// Now call MiInitializePrototypePtes — it will re-encode everything canonically.
	// Since Sub+0x40 (Segment->FirstMappedVa seen via Sub) is NULL it takes the
	// demand-zero path, reads protIdx from Sub+0x20, and calls MiMakeDemandZeroPte again.
	if (gSymInfo.MiInitializePrototypePtes && gInit.NtBaseOffset) {
		typedef VOID(*PFN_INIT)(PVOID pteBase, ULONG64 numPtes, PVOID subsection, ULONG isPagefile);
		PFN_INIT fnInit = (PFN_INIT)(gInit.NtBaseOffset + gSymInfo.MiInitializePrototypePtes);
		__try {
			fnInit(pPTEs, totalPages, pSub, 1);
			DbgPrint("[+] AllocateSubsectionChain: MiInitializePrototypePtes succeeded\n");
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrint("[-] AllocateSubsectionChain: MiInitializePrototypePtes raised %08X — manual PTEs remain\n",
				GetExceptionCode());
		}
	}

	// PtesInSubsection [Sub+0x2C]
	*(ULONG*)((ULONG_PTR)pSub + 0x2C) = (ULONG)totalPages;

	// StartingSector [Sub+0x28] = 0 (first sub starts at page 0)
	*(ULONG*)((ULONG_PTR)pSub + 0x28) = 0;

	// SubsectionBase self-link LIST_ENTRY [Sub+0x50]
	// MiCreatePagingFileMap+0x273: lea rax,[rdx+50h] / mov [rax+8],rax / mov [rax],rax
	PVOID pSubLink = (PVOID)((ULONG_PTR)pSub + 0x50);
	*(PVOID*)((ULONG_PTR)pSub + 0x50) = pSubLink;
	*(PVOID*)((ULONG_PTR)pSub + 0x58) = pSubLink;

	// Terminate subsection chain: next ptr [Sub+0x10] = NULL
	*(PVOID*)((ULONG_PTR)pSub + 0x10) = NULL;

	// ── Initialise _SEGMENT ───────────────────────────────────────────
	// ControlArea [Seg+0x00] → CA
	*(PVOID*)((ULONG_PTR)pSeg + 0x00) = pCA;

	// TotalNumberOfPtes [Seg+0x08]
	*(ULONG64*)((ULONG_PTR)pSeg + 0x08) = totalPages;

	// NumberOfCommittedPages [Seg+0x10] = totalPages
	// Set directly instead of calling MiUpdateControlAreaCommitCount.
	// MiUpdateControlAreaCommitCount registers in the global pagefile commit
	// tracking (SharedCommitNode list). Since we are not truly pagefile-backed,
	// registering there causes MiRemoveSharedCommitNode to crash on process exit
	// when it tries to dereference the misregistered node.
	// MiQueryAddressState reads the prototype PTE protection bits (not this field)
	// to decide MEM_COMMIT, so setting it here is sufficient for correct VirtualQuery.
	*(ULONG64*)((ULONG_PTR)pSeg + 0x10) = totalPages;

	// SizeOfSegment [Seg+0x18] = totalPages * 0x1000
	*(ULONG64*)((ULONG_PTR)pSeg + 0x18) = totalPages << 12;

	// PrototypePte [Seg+0x40] → pPTEs
	// MiLocateProtoPte and MiDispatchFault use Seg+0x40 as the PTE array base.
	// DO NOT write pPTEs to Seg+0x30 — that is the u1 union which contains
	// ImageCommitment / CreatingProcessId / SharedCommitNode depending on section
	// type. Corrupting it causes MiRemoveSharedCommitNode to crash on process exit.
	*(PVOID*)((ULONG_PTR)pSeg + 0x40) = pPTEs;

	*ppControlArea = pCA;
	*ppSegment     = pSeg;
	*ppProtoPTEs   = pPTEs;
	return STATUS_SUCCESS;
}

static BOOLEAN ProcessHasControlArea(PEPROCESS EProcess, ULONG64 targetCA,
	DWORD VADRootOffset, DWORD MMVADSubsection, DWORD MMVADLeft, DWORD MMVADRight) {
	if (!EProcess || !targetCA) return FALSE;

	PVOID root = *(PVOID*)((ULONG_PTR)EProcess + VADRootOffset);
	if (!root || !MmIsAddressValid(root)) return FALSE;

	// Iterative walk — reuse a small stack to avoid kernel stack overflow
#define SHARE_STACK_SIZE 512
	PVOID stack[SHARE_STACK_SIZE];
	int top = 0;
	stack[top++] = root;

	while (top > 0) {
		PVOID node = stack[--top];
		if (!node || !MmIsAddressValid(node)) continue;

		// Probe Subsection pointer at MMVADSubsection offset
		ULONG_PTR* subPtr = (ULONG_PTR*)((ULONG_PTR)node + MMVADSubsection);
		if (MmIsAddressValid(subPtr)) {
			ULONG_PTR subsection = *subPtr;
			if (subsection && MmIsAddressValid((PVOID)subsection)) {
				ULONG_PTR* caPtr = (ULONG_PTR*)subsection;
				if (MmIsAddressValid(caPtr) && *caPtr == (ULONG_PTR)targetCA)
					return TRUE;
			}
		}

		PVOID right = *(PVOID*)((ULONG_PTR)node + MMVADRight);
		PVOID left  = *(PVOID*)((ULONG_PTR)node + MMVADLeft);
		if (right && MmIsAddressValid(right) && top < SHARE_STACK_SIZE - 1) stack[top++] = right;
		if (left  && MmIsAddressValid(left)  && top < SHARE_STACK_SIZE - 1) stack[top++] = left;
	}
	return FALSE;
}

// After the main walk fills gSection, enumerate all processes and count how many
// have a VAD node pointing to each unique ControlArea.
VOID FillSharedProcessCounts(
	DWORD EProcActiveProcessLinks,
	DWORD VADRootOffset,
	DWORD MMVADSubsection,
	DWORD MMVADLeft,
	DWORD MMVADRight) {

	PVAD_NODE nodes = (PVAD_NODE)gSection;
	ULONG nodeCount = (ULONG)(gViewSize / sizeof(VAD_NODE));

	// Collect unique non-zero ControlArea pointers from the node buffer
#define MAX_UNIQUE_CA 1024
	ULONG64 uniqueCA[MAX_UNIQUE_CA];
	ULONG   caCount[MAX_UNIQUE_CA];
	ULONG   uniqueCount = 0;

	for (ULONG i = 0; i < nodeCount; i++) {
		if (nodes[i].Level == 0 || nodes[i].ControlAreaPtr == 0) continue;
		ULONG64 ca = nodes[i].ControlAreaPtr;
		BOOLEAN found = FALSE;
		for (ULONG j = 0; j < uniqueCount; j++) {
			if (uniqueCA[j] == ca) { found = TRUE; break; }
		}
		if (!found && uniqueCount < MAX_UNIQUE_CA) {
			uniqueCA[uniqueCount] = ca;
			caCount[uniqueCount]  = 0;
			uniqueCount++;
		}
	}

	// Walk the process list and count matches for each unique CA
	PVOID currEProc = PsGetCurrentProcess();
	PVOID startEProc = currEProc;
	PLIST_ENTRY listEntry = (PLIST_ENTRY)((ULONG_PTR)currEProc + EProcActiveProcessLinks);

	do {
		if (!MmIsAddressValid(currEProc)) break;
		for (ULONG j = 0; j < uniqueCount; j++) {
			if (ProcessHasControlArea(currEProc, uniqueCA[j],
				VADRootOffset, MMVADSubsection, MMVADLeft, MMVADRight))
				caCount[j]++;
		}
		listEntry = listEntry->Flink;
		if (!MmIsAddressValid(listEntry)) break;
		currEProc = (PVOID)((ULONG_PTR)listEntry - EProcActiveProcessLinks);
	} while (currEProc != startEProc);

	// Write counts back into node buffer
	for (ULONG i = 0; i < nodeCount; i++) {
		if (nodes[i].Level == 0 || nodes[i].ControlAreaPtr == 0) continue;
		for (ULONG j = 0; j < uniqueCount; j++) {
			if (uniqueCA[j] == nodes[i].ControlAreaPtr) {
				nodes[i].SharedProcessCount = caCount[j];
				break;
			}
		}
	}
}

VOID WalkVAD(PEPROCESS TargetProcess,
	DWORD VADRootOffset,
	DWORD StartingVpnOffset,
	DWORD EndingVpnOffset,
	DWORD Left,
	DWORD Right,
	DWORD MMVADSubsection,
	DWORD MMVADControlArea,
	DWORD MMVADCAFilePointer,
	DWORD MMCAFlags,
	DWORD FILEOBJECTFileName,
	unsigned long long targetAdr) {

	PVOID* pVADRoot = (PVOID*)((ULONG_PTR)TargetProcess + VADRootOffset);
	DbgPrint("[*] WalkVAD: TargetProcess: 0x%llx | VADRoot: 0x%llx\n", TargetProcess, *pVADRoot);
	if (!MmIsAddressValid(*pVADRoot)) {
		DbgPrint("[-] VAD tree is empty | *pVADRoot: 0x%llx -> TargetProcess: 0x%llx + VADRootOffset: 0x%lx\n", *pVADRoot, TargetProcess, VADRootOffset);
		return;
	}
	// Variables to track statistics
	ULONG totalVADs = 0;
	ULONG totalLevels = 0;
	ULONG maxDepth = 0;
	gSecVADIndex = 0;
	gCurrFileNameOffset = 0;

	// Iterative stack-safe traversal
	WalkVADIterative(*pVADRoot, StartingVpnOffset, EndingVpnOffset, Left, Right,
		&totalVADs, &totalLevels, &maxDepth, MMVADSubsection, MMVADControlArea, MMVADCAFilePointer, MMCAFlags, FILEOBJECTFileName,
		targetAdr);

	// Calculate and print statistics
	ULONG avgLevel = (totalVADs > 0) ? totalLevels / totalVADs : 0;
	ULONG avgLevelFrac = (totalVADs > 0) ? ((totalLevels * 100) / totalVADs) % 100 : 0;
	DbgPrint("Total VADs: %lu, average level: %lu.%02lu, maximum depth: %lu\n\n",
		totalVADs, avgLevel, avgLevelFrac, maxDepth);
}
